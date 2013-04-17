<?php

/**
 * @defgroup plugins_implicitAuth_cas
 */

/**
 * @file plugins/implicitAuth/cas/index.php
 *
 * Copyright (c) 2013 Steven Marsden
 * Distributed under the GNU GPL v2. For full terms see the file docs/COPYING.
 *
 * @ingroup plugins_implicitAuth_cas
 * @brief Wrapper for the CAS plugin.
 *
 */

require_once('CASAuthPlugin.inc.php');

return new CASAuthPlugin();

?>
