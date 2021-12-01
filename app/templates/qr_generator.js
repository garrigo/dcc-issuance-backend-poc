$( document ).ready(function() {
    var page = '{{page}}'
    if (page == 'generated_gp'){
        var payload='{{payload}}';
        var qrString = String(payload);

        // generate new qr code
        // documentation: https://github.com/kozakdenys/qr-code-styling
        // can be improved to make options be selected by user
        qrCode = new QRCodeStyling({
            /*width: 512,
            height: 512,*/
            type: "jpeg",
            data: qrString,
            dotsOptions: {
                color: "#000000",
                type: "square"
            },
            backgroundOptions: {
                color: "#ffffff",
            },
            imageOptions: {
                crossOrigin: "anonymous",
                margin: 20
            },
            qrOptions: { // these two are crucial to get a small QR code
                mode: "Alphanumeric",
                errorCorrectionLevel: 'L'
            }
        });

        // show success message
        document.getElementById('succ-msg').className = "alert alert-success";
        document.getElementById('succ-msg').innerHTML = "QR has been correctly generated.";
        // append qr rectangle to page and show download and signature verification buttons
        qrCode.append(document.getElementById('qrcode-canvas'));
        document.getElementById('download').style.display = "block"; 
    }

});
// on-click listener for the download button
document.getElementById('download').addEventListener('click', function() {
    // download generated image as jpg with a random name
    qrCode.download({ name: "Green Pass", extension: "jpeg"});
}, false);
