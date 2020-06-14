const fs = require('fs')
const express = require('express')
const root = '/home/berlin/downloads/';
const app = express()

app.get('/', function (req, res) {

    var path = req.query.path || ''
    if( path && path[path.length-1] != '/') path=path.concat('/')
    var files = fs.readdirSync(root + path)

    var html = ''
    files.forEach(function(file) {
        const ext = file.split('.').pop()
        if (fs.statSync(root + path + file).isDirectory()) {
            html+='<li><a href="?path='+path+file+'">'+file+'</a></li>'
        }   
        else if (ext=='avi') {
            html+='<li><a href="/file/'+Buffer.from(path+file).toString('base64')+'">'+file+'</a></li>'
        }
        else {
            html+='<li><strong>'+file+'</strong></li>'
        }
    })

    res.set('Content-Type', 'text/html').send(html)
})

app.get('/file/:file', function (req, res) {
    
    var file = Buffer.from(req.params.file, 'base64').toString('ascii')
    file = fs.readFileSync(root+file, 'binary');

    res.setHeader('Content-Length', file.length);
    res.write(file, 'binary');
    res.end();
})

app.listen(8000, "127.0.0.1")