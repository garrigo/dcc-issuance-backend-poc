// function hexToBytes(hex) {
//     for (var bytes = [], c = 0; c < hex.length; c += 2)
//         bytes.push(parseInt(hex.substr(c, 2), 16));
//     return bytes;
// }

$( document ).ready(function() {
    var generated = '{{generated}}'
    if (generated){
        var payload='{{payload}}';
        
        if (payload){
            /* iso-8859-1 testing */
            // var decoder = new TextDecoder('iso-8859-1')
            // var bytes = new Uint8Array(hexToBytes(payload))
            // var qrString = decoder.decode(bytes);

            /* https://github.com/zingl/2D-Barcode */
            var src = toGif(quickresponse(payload,'L'), 7, undefined, 3).replace("image/gif", "image/png");

            /* aztec testing */
            // var src = toGif(aztec(payload, 2), 7, undefined, 3)).replace("image/gif", "image/png");

            var image = document.createElement("img");
            image.setAttribute("src", src);
            // show success message
            document.getElementById('succ-msg').className = "alert alert-success";
            document.getElementById('succ-msg').innerHTML = "The QR code has been correctly generated.";
            // append qr rectangle to page and show download and signature verification buttons
            document.getElementById('download-link').setAttribute("href", src);
            document.getElementById("qrcode-canvas").appendChild(image);
            document.getElementById('download').style.display = "block"; 
        }
        else{
            // show error message
            document.getElementById('error-msg').className = "alert alert-danger";
            document.getElementById('error-msg').innerHTML = "An internal error has occurred.";
    
        }
    }
});
