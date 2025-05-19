const path = require("path");
const express = require("express");
var bodyParser = require('body-parser')
const cors = require('cors');
const app=express();
app.use(express.json());
   
app.use(express.static("public"));

const {spawn}=require('child_process');

app.get('/',(req,res)=>{
    res.sendFile(path.resolve(__dirname, 'index.html'));
    
})
app.post("/", async function (request, response) {//получилось
    if(!request.body) return response.sendStatus(400);
    const userName = request.body.name;
    url=userName
    content="1"
    
    const myPromise1=new Promise(function(resolve,reject){
        const childPython=spawn('python',['script.py', url]);
        
        childPython.stdout.on('data', (data)=>{
            const data2=data.toString();
            console.log("XSS: ", data2)
            content= JSON.parse(data2);
            resolve(content);
        })
        childPython.stderr.on('data', (data) => { 
            console.error(`stderr: ${data}`);
        });
        childPython.on('error', (err) => {
            reject(err)
        });
        childPython.on('close', (code)=>{
            console.log(`child process exited with code ${code}`);
        })
    })
    const myPromise2=new Promise(function(resolve,reject){
        const childPython=spawn('python',['sqlinjection.py', url]);
        
        childPython.stdout.on('data', (data)=>{
            const data2=data.toString();
            console.log("SQL: ", data2)
            content= JSON.parse(data2);
            resolve(content);
        })
        childPython.stderr.on('data', (data) => { 
            console.error(`stderr: ${data}`);
        });
        childPython.on('error', (err) => {
            reject(err)
        });
        childPython.on('close', (code)=>{
            console.log(`child process exited with code ${code}`);
        })
    })
   
    const [data1, data2] = await Promise.all([myPromise1, myPromise2]);

    const data = [data1, data2];
    response.send(data);

    
});
app.listen(3000, ()=>console.log("Сервер запущен по адресу http://localhost:3000"))


