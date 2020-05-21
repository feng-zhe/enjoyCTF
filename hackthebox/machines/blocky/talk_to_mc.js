var mc = require('minecraft-protocol');
var client = mc.createClient({
    host: "10.10.10.37", // optional
    port: 25565, // optional
    username: "email@example.com",
    password: "12345678",
});
client.on('chat', function(packet) {
    // Listen for chat messages and echo them back.
    var jsonMsg = JSON.parse(packet.message);
    console.log(jsonMsg);
    if (jsonMsg.translate == 'chat.type.announcement' || jsonMsg.translate == 'chat.type.text') {
        var username = jsonMsg.with[0].text;
        var msg = jsonMsg.with[1];
        if (username === client.username) return;
        client.write('chat', {
            message: msg.text
        });
    }
});
