
function onSignIn(googleUser) {
    var id_token = googleUser.getAuthResponse().id_token;
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://localhost:5000/gconnect');
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.send('idtoken=' + id_token + '&state=' + STATE);
}

function signOut() {
    var auth2 = gapi.auth2.getAuthInstance();
    auth2.signOut().then(function () {
        console.log("User signed out from google.. making post request to delete credentials data from flask");
        var xhr = new XMLHttpRequest();
        xhr.open('POST', 'http://localhost:5000/signout');
        xhr.send();
    });
}

function signinCallback(authResult) {
    if (authResult['code']) {
        //console.log(authResult['code']);
        $('#signinButton').attr('style, display: none');
        $.ajax({
            type: 'POST',
            url: '/gconnect?state='+state,
            processData: false,
            contentType: 'application/octet-strem; charset=utf-8',
            data: authResult['code'],
            success: function(result) {
                if (result) {
                    $('#result').html('Login Successfull!</br>'
                                    + result
                                    + '</br>Redirecting...')
                    setTimeout(function() {
                        window.location.href = "/";
                    }, 4000);
                } else if (authResult['error']) {
                    console.log('There was an error: ' + authResult['error']);
                }
            }
        })
    } else {
        $('#result').html('Failed to make a server-side call. Check your configuration and console');
    }
}
