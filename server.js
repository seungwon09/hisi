const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
app.use(express.json());

app.set("trust proxy", 1);

/* ===== 세션 ===== */
app.use(session({
    secret: process.env.SESSION_SECRET || "dev-secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: true,
        sameSite: "lax"
    }
}));

/* ===== DB ===== */
const dbPath = path.join(__dirname, "data.db");
const backupPath = path.join(__dirname, "backup.db");

let db;
function connectDB() {
    db = new sqlite3.Database(dbPath);
}
connectDB();

/* ===== 암호화 ===== */
const SECRET_KEY = crypto.createHash("sha256")
.update(process.env.DATA_KEY || "data-secret")
.digest();

function encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
    let enc = cipher.update(text, "utf8", "hex");
    enc += cipher.final("hex");
    return iv.toString("hex") + ":" + enc;
}

function decrypt(text) {
    const parts = text.split(":");
    const iv = Buffer.from(parts[0], "hex");
    const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
    let dec = decipher.update(parts[1], "hex", "utf8");
    dec += decipher.final("utf8");
    return dec;
}

/* ===== 테이블 ===== */
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT, parent_id INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, text TEXT, category_id INTEGER)`);
});

/* ===== 계정 ===== */
(async () => {
    const hash = await bcrypt.hash("SkY!29#river$T3", 10);
    db.get("SELECT * FROM users WHERE username=?", ["qx7m_lz2k9"], (e, u) => {
        if (!u) db.run("INSERT INTO users (username,password) VALUES (?,?)", ["qx7m_lz2k9", hash]);
    });
})();

/* ===== 자동 백업 ===== */
setInterval(() => {
    if (fs.existsSync(dbPath)) {
        fs.copyFileSync(dbPath, backupPath);
        fs.utimesSync(backupPath, new Date(), new Date());
    }
}, 60000);

/* ===== ACCESS CODE ===== */
const ACCESS_CODE = "839271";

app.post("/access", (req, res) => {
    if (req.body.code === ACCESS_CODE) {
        req.session.access = true;
        res.sendStatus(200);
    } else {
        res.sendStatus(403);
    }
});

/* ===== 정적 ===== */
app.use(express.static(__dirname));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

/* ===== main 보호 ===== */
app.get("/main.html", (req, res) => {
    if (!req.session.access) return res.redirect("/");
    res.sendFile(path.join(__dirname, "main.html"));
});

/* ===== 로그인 ===== */
app.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.get("SELECT * FROM users WHERE username=?", [username], async (e, u) => {
        if (!u) return res.sendStatus(401);
        if (!(await bcrypt.compare(password, u.password))) return res.sendStatus(401);

        req.session.auth = true;
        res.sendStatus(200);
    });
});

/* ===== 인증 ===== */
function auth(req, res, next) {
    if (!req.session.auth) return res.sendStatus(403);
    next();
}

/* ===== 카테고리 ===== */
app.get("/categories", auth, (req, res) => {
    db.all("SELECT * FROM categories", (e, r) => res.json(r));
});

app.post("/categories", auth, (req, res) => {
    const { name, parent_id } = req.body;
    db.run("INSERT INTO categories (name,parent_id) VALUES (?,?)",
        [name, parent_id ? Number(parent_id) : null],
        () => res.end()
    );
});

/* ===== 데이터 ===== */
app.get("/data", auth, (req, res) => {
    db.all("SELECT * FROM data", (e, r) => {
        const result = r.map(x => ({ ...x, text: decrypt(x.text) }));
        res.json(result);
    });
});

app.post("/data", auth, (req, res) => {
    const enc = encrypt(req.body.text);
    db.run("INSERT INTO data (text,category_id) VALUES (?,?)",
        [enc, req.body.category_id],
        () => res.end()
    );
});

/* ===== 로그아웃 ===== */
app.get("/logout", (req, res) => {
    req.session.destroy(() => res.redirect("/"));
});

/* ===== 백업 ===== */
app.get("/backup", (req, res) => {
    if (!req.session.auth) return res.sendStatus(403);
    fs.copyFileSync(dbPath, backupPath);
    res.download(dbPath);
});

/* ===== 복구 ===== */
app.post("/restore", (req, res) => {
    if (!req.session.auth) return res.sendStatus(403);
    if (!fs.existsSync(backupPath)) return res.sendStatus(404);

    db.close(() => {
        fs.copyFileSync(backupPath, dbPath);
        connectDB();
        res.end();
    });
});

/* ===== 실행 ===== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running"));
