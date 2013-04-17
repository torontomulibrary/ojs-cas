<?php

/**
 * @file plugins/implicitAuth/cas/CASAuthPlugin.inc.php
 *
 * Copyright (c) 2013 Steven Marsden
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @class CASAuthPlugin
 * @ingroup plugins_implicitAuth_cas
 *
 * @brief CAS plugin class
 */

import('classes.plugins.ImplicitAuthPlugin');

class CASAuthPlugin extends ImplicitAuthPlugin {

	function register($category, $path) {

		// We use the callback mechanism to call the implicitAuth function.
		//
		// If there ends up being another implicitAuth plugin - then this registration statement
		// should be removed - so that the other plugin gets called

		HookRegistry::register('ImplicitAuthPlugin::implicitAuth', array(&$this, 'implicitAuth'));

		$success = parent::register($category, $path);
		$this->addLocaleData();
		return $success;
	}

	function getName() {
		return "CASAuthPlugin";
	}

	function getDisplayName() {
		return __('plugins.implicitAuth.cas.displayName');
	}

	function getDescription() {
		return __('plugins.implicitAuth.cas.description');
	}

	/**
	 * Return true that this is a site-wide plugin (over-riding superclass setting).
	 */

	function isSitePlugin() {
		return true;
	}

	// Log a user in after they have been authenticated via CAS

	function implicitAuth($hookname, $args) {
			// Set retuser to point to the user that was passed by reference
			$retuser =& $args[0];

			// Get email from header -- after consulting the map
			$email_key = Config::getVar('security', 'implicit_auth_header_email');
			if ($email_key == "") die("Implicit Auth enabled in config file - but config variable implicit_auth_header_email is not defined.");

			// If we can't find the user's email send back to login screen (for the lack of something better to do)
			if (!isset($_SERVER[$email_key])) {
				syslog(LOG_ERR, "Implicit Auth enabled in config file - but expected header variable not found.");
				Validation::logout();
				Validation::redirectLogin();
			}

			$email = $_SERVER[$email_key];

			// Get the user dao - so we can look up the user
			$userDao =& DAORegistry::getDAO('UserDAO');

			// Get the user by email address
			$user =& $userDao->getUserByEmail($email);

			if (isset($user)) {
				syslog(LOG_ERR, "Found user by email: " . $email . " Returning user.");
				syslog(LOG_ERR, "Users authstr: " . $user->getAuthStr());

				$user->setAuthStr($email);
				$userDao->updateObject($user);

				// pass through user session variables
				$sessionManager =& SessionManager::getManager();
				$session =& $sessionManager->getUserSession();
				$session->setIpAddress($_SERVER['HTTP_CLIENT_IP']);

				$sessionDao =& DAORegistry::getDAO('SessionDAO');
				$sessionDao->updateObject($session);

				// Go see if this user should be made an admin
				CASAuthPlugin::implicitAuthAdmin($user->getId(), $user->getAuthStr());

				$retuser = $user;
				return true;
			}

			// User not found by email - they are new, so just create them
			$user = $this->registerUserFromCAS();

			// Go see if this new user should be made an admin

			CASAuthPlugin::implicitAuthAdmin($user->getId(), $user->getAuthStr());

			$retuser = $user;
			return true;
	}

	/**
	 * Register a new user. See classes/user/form/RegistrationForm.inc.php - for how this is done for registering a user in a non-CAS environment.
	 */

	function registerUserFromCAS() {

		// Grab the names of the header fields from the config file

		$uin = Config::getVar('security', 'implicit_auth_header_uin');
		$email = Config::getVar('security', 'implicit_auth_header_email');

		// Create a new user object and set it's fields from the header variables

		$user = new User();

		$user->setAuthStr($_SERVER[$email]); # Auth string is email
		$user->setUsername($_SERVER[$uin]);  # Username is UIN

		$user->setEmail($_SERVER[$email]);
		$user->setDateRegistered(Core::getCurrentDate());

		// Set the user's  password to their email address. This may or may not be necessary
		$user->setPassword(Validation::encryptCredentials($user->getUsername(), $user->getEmail()));

		// Now go insert the user in the db

		$userDao =& DAORegistry::getDAO('UserDAO');
		$userDao->insertUser($user);

		$userId = $user->getId();

		if (!$userId) {
			return false;
		}

		// Go put the user into the session and return it.
//		$sessionManager =& SessionManager::getManager();
//		$session =& $sessionManager->getUserSession();
//		$session->setSessionVar('username', $user->getUsername());

		return $user;
	}

	// If this user is in the list of admins then make sure they are set up as an admin.
	// If they are not in the list - make sure they are not an admin. This is so you can
	// take someone off the admin list - and their admin privelege will be revoked.

	function implicitAuthAdmin($userID, $authStr) {

		$adminstr=Config::getVar('security', "implicit_auth_admin_list");

		$adminlist=explode(" ", $adminstr);

		$key = array_search($authStr, $adminlist);

		$roleDao =& DAORegistry::getDAO('RoleDAO');

		// If they are in the list of users who should be admins

		if ($key !== false) {

			// and if they are not already an admin

			if(!$roleDao->userHasRole(0, $userID, ROLE_ID_SITE_ADMIN)) {

				syslog(LOG_ERR, "Implicit Auth - Making Admin: " . $userID);

				// make them an admin

				$role = new Role();
				$role->setJournalId(0);
				$role->setUserId($userID);
				$role->setRoleId(ROLE_ID_SITE_ADMIN);
				$roleDao->insertRole($role);
			}
		} else {

			// If they are not in the admin list - then be sure they are not an admin in the role table

			syslog(LOG_ERR, "removing admin for: " . $userID);

			$roleDao->deleteRoleByUserId($userID,0, ROLE_ID_SITE_ADMIN);
		}

	}
}

?>
