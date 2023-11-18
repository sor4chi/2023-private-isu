package main

import (
	crand "crypto/rand"
	"crypto/sha512"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bradfitz/gomemcache/memcache"
	gsm "github.com/bradleypeabody/gorilla-sessions-memcache"
	"github.com/go-chi/chi/v5"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
	"github.com/jmoiron/sqlx"
)

var (
	db    *sqlx.DB
	store *gsm.MemcacheStore
)

const (
	postsPerPage  = 20
	ISO8601Format = "2006-01-02T15:04:05-07:00"
	UploadLimit   = 10 * 1024 * 1024 // 10mb
)

type User struct {
	ID          int       `db:"id"`
	AccountName string    `db:"account_name"`
	Passhash    string    `db:"passhash"`
	Authority   int       `db:"authority"`
	DelFlg      int       `db:"del_flg"`
	CreatedAt   time.Time `db:"created_at"`
}

type Post struct {
	ID           int       `db:"id"`
	UserID       int       `db:"user_id"`
	Imgdata      []byte    `db:"imgdata"`
	Body         string    `db:"body"`
	Mime         string    `db:"mime"`
	CreatedAt    time.Time `db:"created_at"`
	CommentCount int
	Comments     []Comment
	User         User
	CSRFToken    string
}

type Comment struct {
	ID        int       `db:"id"`
	PostID    int       `db:"post_id"`
	UserID    int       `db:"user_id"`
	Comment   string    `db:"comment"`
	CreatedAt time.Time `db:"created_at"`
	User      User
}

var fmap = template.FuncMap{
	"imageURL": imageURL,
}

func init() {
	memdAddr := os.Getenv("ISUCONP_MEMCACHED_ADDRESS")
	if memdAddr == "" {
		memdAddr = "localhost:11211"
	}
	memcacheClient := memcache.New(memdAddr)
	store = gsm.NewMemcacheStore(memcacheClient, "iscogram_", []byte("sendagaya"))
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
}

func dbInitialize() {
	sqls := []string{
		"DELETE FROM users WHERE id > 1000",
		"DELETE FROM posts WHERE id > 10000",
		"DELETE FROM comments WHERE id > 100000",
		"UPDATE users SET del_flg = 0",
		"UPDATE users SET del_flg = 1 WHERE id % 50 = 0",
	}

	for _, sql := range sqls {
		db.Exec(sql)
	}
}

func tryLogin(accountName, password string) *User {
	u := User{}
	err := db.Get(&u, "SELECT * FROM users WHERE account_name = ? AND del_flg = 0", accountName)
	if err != nil {
		return nil
	}

	if calculatePasshash(u.AccountName, password) == u.Passhash {
		return &u
	} else {
		return nil
	}
}

func validateUser(accountName, password string) bool {
	return regexp.MustCompile(`^[0-9a-zA-Z_]{3,}$`).MatchString(accountName) &&
		regexp.MustCompile(`^[0-9a-zA-Z_]{6,}$`).MatchString(password)
}

func digest(src string) string {
	h := sha512.New()
	h.Write([]byte(src))
	return fmt.Sprintf("%x", h.Sum(nil))

}

func calculateSalt(accountName string) string {
	return digest(accountName)
}

func calculatePasshash(accountName, password string) string {
	return digest(password + ":" + calculateSalt(accountName))
}

func getSession(r *http.Request) *sessions.Session {
	session, _ := store.Get(r, "isuconp-go.session")

	return session
}

func getSessionUser(r *http.Request) User {
	session := getSession(r)
	uid, ok := session.Values["user_id"]
	if !ok || uid == nil {
		return User{}
	}

	u := User{}

	err := db.Get(&u, "SELECT * FROM `users` WHERE `id` = ?", uid)
	if err != nil {
		return User{}
	}

	return u
}

func getFlash(w http.ResponseWriter, r *http.Request, key string) string {
	session := getSession(r)
	value, ok := session.Values[key]

	if !ok || value == nil {
		return ""
	} else {
		delete(session.Values, key)
		session.Save(r, w)
		return value.(string)
	}
}

func makePosts(results []Post, allComments bool) ([]Post, error) {
	var posts []Post

	postIds := make([]int, len(results))
	postUserIds := make([]int, len(results))
	for i, p := range results {
		postIds[i] = p.ID
		postUserIds[i] = p.UserID
	}
	sql, params, err := sqlx.In("SELECT * FROM `comments` WHERE `post_id` IN (?) ORDER BY `created_at` DESC", postIds)
	if err != nil {
		return nil, err
	}
	var allPostsComments []Comment
	err = db.Select(&allPostsComments, sql, params...)
	if err != nil {
		return nil, err
	}

	commentsMap := map[int][]Comment{}
	for _, c := range allPostsComments {
		commentsMap[c.PostID] = append(commentsMap[c.PostID], c)
	}

	allCommentsUserIds := make([]int, len(allPostsComments)+len(postUserIds))
	allCommentsUserIdsMap := map[int]struct{}{}
	for i, p := range postUserIds {
		allCommentsUserIds[i] = p
		allCommentsUserIdsMap[p] = struct{}{}
	}
	for _, c := range allPostsComments {
		if _, ok := allCommentsUserIdsMap[c.UserID]; !ok {
			allCommentsUserIds = append(allCommentsUserIds, c.UserID)
			allCommentsUserIdsMap[c.UserID] = struct{}{}
		}
	}

	sql, params, err = sqlx.In("SELECT * FROM `users` WHERE `id` IN (?)", allCommentsUserIds)
	if err != nil {
		return nil, err
	}

	var allCommentsUsers []User
	err = db.Select(&allCommentsUsers, sql, params...)
	if err != nil {
		return nil, err
	}

	usersMap := map[int]User{}
	for _, u := range allCommentsUsers {
		usersMap[u.ID] = u
	}

	for _, p := range results {
		comments := commentsMap[p.ID]
		p.CommentCount = len(comments)
		if !allComments && len(comments) > 3 {
			comments = comments[len(comments)-3:]
		}
		for i := 0; i < len(comments); i++ {
			comments[i].User = usersMap[comments[i].UserID]
		}
		// reverse
		for i, j := 0, len(comments)-1; i < j; i, j = i+1, j-1 {
			comments[i], comments[j] = comments[j], comments[i]
		}
		p.Comments = comments
		p.User = usersMap[p.UserID]
		posts = append(posts, p)
	}

	return posts, nil
}

func imageURL(p Post) string {
	ext := ""
	if p.Mime == "image/jpeg" {
		ext = ".jpg"
	} else if p.Mime == "image/png" {
		ext = ".png"
	} else if p.Mime == "image/gif" {
		ext = ".gif"
	}

	return "/image/" + strconv.Itoa(p.ID) + ext
}

func isLogin(u User) bool {
	return u.ID != 0
}

func getCSRFToken(r *http.Request) string {
	session := getSession(r)
	csrfToken, ok := session.Values["csrf_token"]
	if !ok {
		return ""
	}
	return csrfToken.(string)
}

func secureRandomStr(b int) string {
	k := make([]byte, b)
	if _, err := crand.Read(k); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", k)
}

func getTemplPath(filename string) string {
	return path.Join("templates", filename)
}

func getInitialize(w http.ResponseWriter, r *http.Request) {
	dbInitialize()
	w.WriteHeader(http.StatusOK)
}

var getLoginTemplate = template.Must(template.ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("login.html")),
)

func getLogin(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)

	if isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	getLoginTemplate.Execute(w, struct {
		Me    User
		Flash string
	}{me, getFlash(w, r, "notice")})
}

func postLogin(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	u := tryLogin(r.FormValue("account_name"), r.FormValue("password"))

	if u != nil {
		session := getSession(r)
		session.Values["user_id"] = u.ID
		session.Values["csrf_token"] = secureRandomStr(16)
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
	} else {
		session := getSession(r)
		session.Values["notice"] = "アカウント名かパスワードが間違っています"
		session.Save(r, w)

		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

var getRegisterTemplate = template.Must(template.ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("register.html")),
)

func getRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	getRegisterTemplate.Execute(w, struct {
		Me    User
		Flash string
	}{User{}, getFlash(w, r, "notice")})
}

func postRegister(w http.ResponseWriter, r *http.Request) {
	if isLogin(getSessionUser(r)) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	accountName, password := r.FormValue("account_name"), r.FormValue("password")

	validated := validateUser(accountName, password)
	if !validated {
		session := getSession(r)
		session.Values["notice"] = "アカウント名は3文字以上、パスワードは6文字以上である必要があります"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	exists := 0
	// ユーザーが存在しない場合はエラーになるのでエラーチェックはしない
	db.Get(&exists, "SELECT 1 FROM users WHERE `account_name` = ?", accountName)

	if exists == 1 {
		session := getSession(r)
		session.Values["notice"] = "アカウント名がすでに使われています"
		session.Save(r, w)

		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	query := "INSERT INTO `users` (`account_name`, `passhash`) VALUES (?,?)"
	result, err := db.Exec(query, accountName, calculatePasshash(accountName, password))
	if err != nil {
		log.Print(err)
		return
	}

	session := getSession(r)
	uid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}
	session.Values["user_id"] = uid
	session.Values["csrf_token"] = secureRandomStr(16)
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

func getLogout(w http.ResponseWriter, r *http.Request) {
	session := getSession(r)
	delete(session.Values, "user_id")
	session.Options = &sessions.Options{MaxAge: -1}
	session.Save(r, w)

	http.Redirect(w, r, "/", http.StatusFound)
}

var getIndexTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("index.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

var latestGetIndexResponse = []Post{}

func getIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	csrfToken := getCSRFToken(r)

	var posts []Post
	if len(latestGetIndexResponse) > 0 {
		for _, p := range posts {
			posts = latestGetIndexResponse
			p.CSRFToken = getCSRFToken(r)
		}
	} else {

		results := []Post{}

		const query = `
		SELECT
			posts.id,
			posts.user_id,
			posts.body,
			posts.mime,
			posts.created_at
		FROM
			posts
		JOIN
			users ON users.id = posts.user_id
		WHERE
			users.del_flg = 0
		ORDER BY posts.created_at DESC
		LIMIT ?
	`

		err := db.Select(&results, query, postsPerPage)
		if err != nil {
			log.Print(err)
			return
		}

		posts, err = makePosts(results, false)
		if err != nil {
			log.Print(err)
			return
		}
	}

	for _, p := range posts {
		p.CSRFToken = csrfToken
	}

	getIndexTemplate.Execute(w, struct {
		Posts     []Post
		Me        User
		CSRFToken string
		Flash     string
	}{posts, me, getCSRFToken(r), getFlash(w, r, "notice")})
}

var getAccountNameTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("user.html"),
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getAccountName(w http.ResponseWriter, r *http.Request) {
	accountName := chi.URLParam(r, "accountName")
	user := User{}

	err := db.Get(&user, "SELECT * FROM `users` WHERE `account_name` = ? AND `del_flg` = 0", accountName)
	if err != nil {
		log.Print(err)
		return
	}

	if user.ID == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}

	wg := sync.WaitGroup{}
	var posts []Post

	wg.Add(1)
	go func() {
		defer wg.Done()
		err = db.Select(&results, "SELECT `id`, `user_id`, `body`, `mime`, `created_at` FROM `posts` WHERE `user_id` = ? ORDER BY `created_at` DESC LIMIT ?", user.ID, postsPerPage)
		if err != nil {
			log.Print(err)
			return
		}

		csrfToken := getCSRFToken(r)

		posts, err = makePosts(results, false)
		if err != nil {
			log.Print(err)
			return
		}

		for _, p := range posts {
			p.CSRFToken = csrfToken
		}
	}()

	commentCount := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = db.Get(&commentCount, "SELECT COUNT(*) AS count FROM `comments` WHERE `user_id` = ?", user.ID)
		if err != nil {
			log.Print(err)
			return
		}
	}()

	postCount := 0
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = db.Get(&postCount, "SELECT COUNT(`id`) FROM `posts` WHERE `user_id` = ?", user.ID)
		if err != nil {
			log.Print(err)
			return
		}
	}()

	wg.Wait()

	commentedCount := 0
	if postCount > 0 {
		err := db.Get(&commentedCount, "SELECT COUNT(*) AS count FROM `comments` WHERE EXISTS (SELECT `id` FROM `posts` WHERE `user_id` = ? AND `id` = `comments`.`post_id`)", user.ID)
		if err != nil {
			log.Print(err)
			return
		}
	}

	me := getSessionUser(r)

	getAccountNameTemplate.Execute(w, struct {
		Posts          []Post
		User           User
		PostCount      int
		CommentCount   int
		CommentedCount int
		Me             User
	}{posts, user, postCount, commentCount, commentedCount, me})
}

var getPostsTemplate = template.Must(template.New("posts.html").Funcs(fmap).ParseFiles(
	getTemplPath("posts.html"),
	getTemplPath("post.html"),
))

func getPosts(w http.ResponseWriter, r *http.Request) {
	m, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Print(err)
		return
	}
	maxCreatedAt := m.Get("max_created_at")
	if maxCreatedAt == "" {
		return
	}

	t, err := time.Parse(ISO8601Format, maxCreatedAt)
	if err != nil {
		log.Print(err)
		return
	}

	results := []Post{}

	const query = `
		SELECT
			posts.id,
			posts.user_id,
			posts.body,
			posts.mime,
			posts.created_at
		FROM
			posts
		JOIN
			users ON posts.user_id = users.id
		WHERE
			users.del_flg = 0 AND posts.created_at <= ?
		ORDER BY posts.created_at DESC
		LIMIT ?
	`

	err = db.Select(&results, query, t.Format(ISO8601Format), postsPerPage)

	if err != nil {
		log.Print(err)
		return
	}

	csrfToken := getCSRFToken(r)

	posts, err := makePosts(results, false)
	if err != nil {
		log.Print(err)
		return
	}

	for _, p := range posts {
		p.CSRFToken = csrfToken
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	getPostsTemplate.Execute(w, posts)
}

var getPostsIDTemplate = template.Must(template.New("layout.html").Funcs(fmap).ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("post_id.html"),
	getTemplPath("post.html"),
))

func getPostsID(w http.ResponseWriter, r *http.Request) {
	pidStr := chi.URLParam(r, "id")
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	results := []Post{}
	err = db.Select(&results, "SELECT `id`, `user_id`, `mime`, `body`, `created_at` FROM `posts` WHERE `id` = ?", pid)
	if err != nil {
		log.Print(err)
		return
	}

	csrfToken := getCSRFToken(r)

	posts, err := makePosts(results, true)
	if err != nil {
		log.Print(err)
		return
	}

	for _, p := range posts {
		p.CSRFToken = csrfToken
	}

	if len(posts) == 0 {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	p := posts[0]

	me := getSessionUser(r)

	getPostsIDTemplate.Execute(w, struct {
		Post Post
		Me   User
	}{p, me})
}

func postIndex(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		session := getSession(r)
		session.Values["notice"] = "画像が必須です"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	mime := ""
	if file != nil {
		// 投稿のContent-Typeからファイルのタイプを決定する
		contentType := header.Header["Content-Type"][0]
		if strings.Contains(contentType, "jpeg") {
			mime = "image/jpeg"
		} else if strings.Contains(contentType, "png") {
			mime = "image/png"
		} else if strings.Contains(contentType, "gif") {
			mime = "image/gif"
		} else {
			session := getSession(r)
			session.Values["notice"] = "投稿できる画像形式はjpgとpngとgifだけです"
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	}

	filedata, err := io.ReadAll(file)
	if err != nil {
		log.Print(err)
		return
	}

	if len(filedata) > UploadLimit {
		session := getSession(r)
		session.Values["notice"] = "ファイルサイズが大きすぎます"
		session.Save(r, w)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	query := "INSERT INTO `posts` (`user_id`, `mime`, `imgdata`, `body`) VALUES (?,?,?,?)"
	result, err := db.Exec(
		query,
		me.ID,
		mime,
		"0", // dummy
		r.FormValue("body"),
	)
	if err != nil {
		log.Print(err)
		return
	}

	latestGetIndexResponse = []Post{}

	pid, err := result.LastInsertId()
	if err != nil {
		log.Print(err)
		return
	}

	// save image
	go func() {
		err := os.WriteFile("../public"+imageURL(Post{ID: int(pid), Mime: mime}), filedata, 0644)
		if err != nil {
			log.Print(err)
			return
		}
	}()

	http.Redirect(w, r, "/posts/"+strconv.FormatInt(pid, 10), http.StatusFound)
}

func postComment(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	postID, err := strconv.Atoi(r.FormValue("post_id"))
	if err != nil {
		log.Print("post_idは整数のみです")
		return
	}

	query := "INSERT INTO `comments` (`post_id`, `user_id`, `comment`) VALUES (?,?,?)"
	_, err = db.Exec(query, postID, me.ID, r.FormValue("comment"))
	if err != nil {
		log.Print(err)
		return
	}
	for _, r := range latestGetIndexResponse {
		if r.ID == postID {
			latestGetIndexResponse = []Post{}
			break
		}
	}

	http.Redirect(w, r, fmt.Sprintf("/posts/%d", postID), http.StatusFound)
}

var getAdminBannedTemplate = template.Must(template.ParseFiles(
	getTemplPath("layout.html"),
	getTemplPath("banned.html")),
)

func getAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	users := []User{}
	err := db.Select(&users, "SELECT * FROM `users` WHERE `authority` = 0 AND `del_flg` = 0 ORDER BY `created_at` DESC")
	if err != nil {
		log.Print(err)
		return
	}

	getAdminBannedTemplate.Execute(w, struct {
		Users     []User
		Me        User
		CSRFToken string
	}{users, me, getCSRFToken(r)})
}

func postAdminBanned(w http.ResponseWriter, r *http.Request) {
	me := getSessionUser(r)
	if !isLogin(me) {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	if me.Authority == 0 {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	if r.FormValue("csrf_token") != getCSRFToken(r) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}

	err := r.ParseForm()
	if err != nil {
		log.Print(err)
		return
	}

	ids := make([]interface{}, len(r.Form["uid[]"]))
	for i, id := range r.Form["uid[]"] {
		ids[i] = id
	}

	query, args, err := sqlx.In("UPDATE `users` SET `del_flg` = 1 WHERE `id` IN (?)", ids)
	if err != nil {
		log.Print(err)
		return
	}
	_, err = db.Exec(query, args...)
	if err != nil {
		log.Print(err)
		return
	}

	for _, r := range latestGetIndexResponse {
		for _, c := range r.Comments {
			for _, id := range ids {
				if strconv.Itoa(c.UserID) == fmt.Sprintf("%s", id) {
					latestGetIndexResponse = []Post{}
					break
				}
			}
		}
	}

	http.Redirect(w, r, "/admin/banned", http.StatusFound)
}

func main() {
	host := os.Getenv("ISUCONP_DB_HOST")
	if host == "" {
		host = "localhost"
	}
	port := os.Getenv("ISUCONP_DB_PORT")
	if port == "" {
		port = "3306"
	}
	_, err := strconv.Atoi(port)
	if err != nil {
		log.Fatalf("Failed to read DB port number from an environment variable ISUCONP_DB_PORT.\nError: %s", err.Error())
	}
	user := os.Getenv("ISUCONP_DB_USER")
	if user == "" {
		user = "root"
	}
	password := os.Getenv("ISUCONP_DB_PASSWORD")
	dbname := os.Getenv("ISUCONP_DB_NAME")
	if dbname == "" {
		dbname = "isuconp"
	}

	dsn := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true&loc=Local&interpolateParams=true",
		user,
		password,
		host,
		port,
		dbname,
	)

	db, err = sqlx.Open("mysql", dsn)
	if err != nil {
		log.Fatalf("Failed to connect to DB: %s.", err.Error())
	}
	defer db.Close()

	r := chi.NewRouter()

	r.Get("/initialize", getInitialize)
	r.Get("/login", getLogin)
	r.Post("/login", postLogin)
	r.Get("/register", getRegister)
	r.Post("/register", postRegister)
	r.Get("/logout", getLogout)
	r.Get("/", getIndex)
	r.Get("/posts", getPosts)
	r.Get("/posts/{id}", getPostsID)
	r.Post("/", postIndex)
	r.Post("/comment", postComment)
	r.Get("/admin/banned", getAdminBanned)
	r.Post("/admin/banned", postAdminBanned)
	r.Get(`/@{accountName:[a-zA-Z]+}`, getAccountName)

	log.Fatal(http.ListenAndServe(":8080", r))
}
