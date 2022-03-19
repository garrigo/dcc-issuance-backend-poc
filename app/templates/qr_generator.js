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
            var qrString = String(payload);

            /* https://github.com/zingl/2D-Barcode */
            code = quickresponse(payload,'L')
            // code = aztec(payload, 2)
            var image = document.createElement("img");
            image.setAttribute("src", toGif(code, 7));

            // show success message
            document.getElementById('succ-msg').className = "alert alert-success";
            document.getElementById('succ-msg').innerHTML = "QR has been correctly generated.";
            // append qr rectangle to page and show download and signature verification buttons
            document.getElementById("qrcode-canvas").appendChild(image);
            document.getElementById('download').style.display = "block"; 
            // on-click listener for the download button
            document.getElementById('download').addEventListener('click', function() {
                // download generated image as jpg with a random name
                qrCode.download({ name: "DCC", extension: "jpeg"});
            }, false);
        }
        else{
            // show error message
            document.getElementById('error-msg').className = "alert alert-danger";
            document.getElementById('error-msg').innerHTML = "An internal error has occurred.";
    
        }
    }
});
