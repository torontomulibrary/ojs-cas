<?php
	require_once 'CAS.php';

	// Initialize CAS
	phpCAS::client(
		'2.0',  //CAS Version Number
		'cas.example.com', //CAS Server Address
		443, //CAS Server Port
		'/' //CAS Base URI
	);
	$phpCas = new phpCas();

	// Set no SSL validation for the CAS server
	// NB: Is this potentially a security risk?
	if (method_exists($phpCas, 'setNoCasServerValidation')) {
		phpCAS::setNoCasServerValidation();
	}
	unset($phpCas);

	// Check for existing login, force login if it doesn't exist
	if(!phpCAS::isAuthenticated()) {
		phpCAS::forceAuthentication();
	}
	
	// Get username, set it to session
	$username = phpCAS::getUser();

	// Set the user attributes to be passed to OJS
	$opts = array(
		'http'=>array(
			'method'=> "GET",
			'header'=>
				"USER_AGENT: ".$_SERVER['HTTP_USER_AGENT']."\r\n".
				"CLIENT_IP: ".$_SERVER['REMOTE_ADDR']."\r\n".
				"EMAIL: $username@ryerson.ca\r\n".
				"UIN: $username\r\n"
		)
	);

	// Create an HTTP stream and GET the OJS implicitAuth URL
	$context = stream_context_create($opts);
	file_get_contents($_GET['target'], false, $context);
	
	// Send response headers directly to the client verbatim
	foreach($http_response_header as $header) {
		header($header,false);
	}	
	
	// TODO: Log out from CAS so user doesn't remain authenticated after logging out from OJS
//	file_get_contents(phpCAS::getServerLogoutURL(), false, $context);
//    session_unset();
//    session_destroy();
?>
