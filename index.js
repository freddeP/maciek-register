const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
const mysql = require("mysql");
const bcrypt = require("bcryptjs");


app.use(express.static(__dirname+"/public"));
app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(cookieParser());
app.use(cors());

// db-connection
let con = mysql.createConnection({
    host:"localhost",
    user:"root",
    password:"",
    database:"node2020",
    port:"3309"
});



app.get('/register',function(req,res){ 

    res.sendFile(__dirname + "/register_form.html");

});

app.post('/register',async(req,res)=>{

    let user = {...req.body};
    // hasha lösenord
    user.password = await bcrypt.hash(user.password,12);
    // hämta random kod från funktion längst ned i filen
    let code = getRandomCode();
    // kryptera koden 
    let codeHash = await bcrypt.hash(code,12);
    // spara ny user med kod och verified = false
    let query = `
    INSERT INTO users (username,email,password,code,verified)
    VALUES (?,?,?,?,?)
    `;
    let inputs = [user.username,user.email,user.password,codeHash,false];
    con.query(query,inputs,(err,result)=>{
        console.log(err);
        // skriv ut hur länken kommer att se ut i ett email
        console.log(`
        <a href = "/verification/${code}/${result.insertId}">verify<a>
        `);
        err? res.status(406).send(err.message): res.status(200).send("ok");
    });


});

app.get('/verification/:code/:id',function(req,res){

    // skapar 2 variabler från våra params 
    let {id, code} = req.params;

    // hämta aktuell user från db
    let query = "SELECT * FROM users WHERE id = ?";
    // observera async här behövs längre ned i vår callback.
    con.query(query,[id], async (err, data)=>{

        if(!err){
            // hämta code från db
            let hash = data[0].code;
            console.log(hash);
            try {
                let codeCheck = await bcrypt.compare(code,hash);
                console.log(codeCheck);
                if(codeCheck)
                {
                    let updateQuery = `
                    UPDATE users SET verified = true, code ='' WHERE id = ?
                    `;
                    con.query(updateQuery,[id],(err)=>{
                        console.log(err);
                        if(!err) res.send("registration complete");
                        else res.send("registration failed");
                    })

                }
                else
                {
                    res.send("registration failed");
                }
              
            
            } catch (error) {
                res.send(error.message);
            }
            

        }
        




    }); // end con insert

}); // end route

app.listen(4000, ()=>{console.log(4000)});



function getRandomCode(){

    const crypto = require('crypto');
    const code = crypto.randomBytes(6).toString("hex");
    console.log(code);
    return code;
  
}