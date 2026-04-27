const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const session = require("express-session");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
app.use(express.json());

app.use(session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: true
}));

const dbPath = path.join(__dirname, "data.db");
const backupPath = path.join(__dirname, "backup.db");

const SECRET_KEY = crypto.createHash("sha256").update("my-secret-key").digest();

let db;
function connectDB(){ db = new sqlite3.Database(dbPath); }
connectDB();

/* ===== 암호화 ===== */
function encrypt(text){
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, iv);
    let enc = cipher.update(text, "utf8", "hex");
    enc += cipher.final("hex");
    return iv.toString("hex") + ":" + enc;
}

function decrypt(text){
    const parts = text.split(":");
    const iv = Buffer.from(parts[0], "hex");
    const encrypted = parts[1];
    const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, iv);
    let dec = decipher.update(encrypted, "hex", "utf8");
    dec += decipher.final("utf8");
    return dec;
}

/* ===== 테이블 ===== */
db.serialize(()=>{
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)`);
    db.run(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY, name TEXT, parent_id INTEGER)`);
    db.run(`CREATE TABLE IF NOT EXISTS data (id INTEGER PRIMARY KEY, text TEXT, category_id INTEGER)`);
});

/* ===== 초기 계정 ===== */
(async()=>{
    const hash = await bcrypt.hash("SkY!29#river$T3",10);
    db.get("SELECT * FROM users WHERE username=?",["qx7m_lz2k9"],(e,u)=>{
        if(!u) db.run("INSERT INTO users (username,password) VALUES (?,?)",["qx7m_lz2k9",hash]);
    });
})();

/* ===== 자동 백업 ===== */
setInterval(()=>{
    if(fs.existsSync(dbPath)){
        fs.copyFileSync(dbPath, backupPath);
        fs.utimesSync(backupPath,new Date(),new Date());
        console.log("자동 백업");
    }
},60000);

/* ===== 접속 코드 ===== */
const ACCESS_CODE="839271";
app.post("/access",(req,res)=>{
    if(req.body.code===ACCESS_CODE) return res.json({success:true});
    res.status(401).end();
});

/* ===== 로그인 ===== */
app.post("/login",(req,res)=>{
    const {username,password}=req.body;
    db.get("SELECT * FROM users WHERE username=?",[username],async(e,u)=>{
        if(!u) return res.status(401).end();
        if(!(await bcrypt.compare(password,u.password))) return res.status(401).end();
        req.session.auth=true;
        res.json({success:true});
    });
});

/* ===== 카테고리 ===== */
app.get("/categories",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();
    db.all("SELECT * FROM categories",(e,r)=>res.json(r));
});

app.post("/categories",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();
    const {name,parent_id}=req.body;
    db.run("INSERT INTO categories (name,parent_id) VALUES (?,?)",[name,parent_id?Number(parent_id):null],()=>res.end());
});

/* ===== 데이터 ===== */
app.get("/data",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();

    db.all("SELECT * FROM data",(e,r)=>{
        const result = r.map(x=>{
            return {...x, text: decrypt(x.text)};
        });
        res.json(result);
    });
});

app.post("/data",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();

    const enc = encrypt(req.body.text);

    db.run("INSERT INTO data (text,category_id) VALUES (?,?)",
    [enc,req.body.category_id],()=>res.end());
});

app.delete("/data/:id",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();
    db.run("DELETE FROM data WHERE id=?",[req.params.id],()=>res.end());
});

app.put("/data/:id",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();

    const enc = encrypt(req.body.text);

    db.run("UPDATE data SET text=? WHERE id=?",
    [enc,req.params.id],()=>res.end());
});

/* ===== 로그아웃 ===== */
app.get("/logout",(req,res)=>{
    req.session.destroy(()=>res.redirect("/main.html"));
});

/* ===== 백업 ===== */
app.get("/backup",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();
    fs.copyFileSync(dbPath, backupPath);
    res.download(dbPath);
});

/* ===== 복구 ===== */
app.post("/restore",(req,res)=>{
    if(!req.session.auth) return res.status(403).end();
    if(!fs.existsSync(backupPath)) return res.status(404).end();

    db.close(()=>{
        fs.copyFileSync(backupPath, dbPath);
        connectDB();
        res.end();
    });
});

/* ===== 페이지 ===== */
app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.get("/main.html",(req,res)=>res.sendFile(path.join(__dirname,"main.html")));

app.get("/dashboard.html",(req,res)=>{
    if(req.session.auth) return res.sendFile(path.join(__dirname,"dashboard.html"));
    res.status(403).send("접근 금지");
});

/* ===== 실행 ===== */
app.listen(3000,()=>console.log("Server running"));