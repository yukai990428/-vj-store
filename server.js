const express=require("express");
const session=require("express-session");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const multer=require("multer");
const path=require("path");
const fs=require("fs");

const app=express();
const PORT=process.env.PORT||3000;
const db=new Database(path.join(__dirname,"data","vj.db"));
db.pragma("journal_mode=WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS admins(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS products(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 game TEXT NOT NULL,
 price INTEGER NOT NULL,
 description TEXT DEFAULT '',
 image TEXT DEFAULT '',
 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);`);

const adminUser=process.env.ADMIN_USER||"vjadmin";
const adminPass=process.env.ADMIN_PASSWORD||"CHANGE_THIS_PASSWORD";
const existing=db.prepare("SELECT id FROM admins WHERE username=?").get(adminUser);
if(!existing){
  db.prepare("INSERT INTO admins(username,password_hash) VALUES(?,?)")
    .run(adminUser,bcrypt.hashSync(adminPass,12));
  console.log("Admin created:",adminUser);
  if(adminPass==="CHANGE_THIS_PASSWORD") console.log("IMPORTANT: set ADMIN_PASSWORD before production.");
}

fs.mkdirSync(path.join(__dirname,"uploads"),{recursive:true});
const storage=multer.diskStorage({
 destination:(req,file,cb)=>cb(null,path.join(__dirname,"uploads")),
 filename:(req,file,cb)=>{
   const ext=path.extname(file.originalname).toLowerCase();
   cb(null,Date.now()+"-"+Math.random().toString(36).slice(2)+ext);
 }
});
const upload=multer({storage,limits:{fileSize:8*1024*1024},
 fileFilter:(req,file,cb)=>cb(null,/^image\/(jpeg|png|webp|gif)$/.test(file.mimetype))
});

app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(session({
 secret:process.env.SESSION_SECRET||"CHANGE_THIS_SESSION_SECRET",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:false,maxAge:1000*60*60*8}
}));
app.use("/uploads",express.static(path.join(__dirname,"uploads")));
app.use(express.static(__dirname));

function auth(req,res,next){
 if(!req.session.adminId) return res.status(401).json({error:"未登入"});
 next();
}

app.post("/api/login",(req,res)=>{
 const {username,password}=req.body;
 const a=db.prepare("SELECT * FROM admins WHERE username=?").get(username);
 if(!a || !bcrypt.compareSync(password,a.password_hash))
   return res.status(401).json({error:"帳號或密碼錯誤"});
 req.session.adminId=a.id;
 res.json({ok:true});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({loggedIn:!!req.session.adminId}));

app.get("/api/products",(req,res)=>{
 res.json(db.prepare("SELECT * FROM products ORDER BY id DESC").all());
});
app.post("/api/products",auth,upload.single("image"),(req,res)=>{
 const {title,game,price,description}=req.body;
 if(!title||!game||!price) return res.status(400).json({error:"請填寫商品名稱、遊戲與價格"});
 const image=req.file?"/uploads/"+req.file.filename:"";
 const r=db.prepare("INSERT INTO products(title,game,price,description,image) VALUES(?,?,?,?,?)")
  .run(title,game,Number(price),description||"",image);
 res.json({id:r.lastInsertRowid});
});
app.put("/api/products/:id",auth,upload.single("image"),(req,res)=>{
 const old=db.prepare("SELECT * FROM products WHERE id=?").get(req.params.id);
 if(!old) return res.status(404).json({error:"商品不存在"});
 const image=req.file?"/uploads/"+req.file.filename:old.image;
 db.prepare("UPDATE products SET title=?,game=?,price=?,description=?,image=? WHERE id=?")
 .run(req.body.title,req.body.game,Number(req.body.price),req.body.description||"",image,req.params.id);
 res.json({ok:true});
});
app.delete("/api/products/:id",auth,(req,res)=>{
 const old=db.prepare("SELECT * FROM products WHERE id=?").get(req.params.id);
 if(old?.image?.startsWith("/uploads/")){
   const p=path.join(__dirname,old.image);
   if(fs.existsSync(p)) fs.unlinkSync(p);
 }
 db.prepare("DELETE FROM products WHERE id=?").run(req.params.id);
 res.json({ok:true});
});
app.listen(PORT,()=>console.log(`VJ Store running: http://localhost:${PORT}`));
