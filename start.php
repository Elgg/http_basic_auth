<?php
    /**
	 * Elgg Basic HTTP authentication
	 * 
	 * @package ElggHTTPAuth
	 * @license http://www.gnu.org/licenses/old-licenses/gpl-2.0.html GNU Public License version 2
	 * @author Misja Hoebe <misja@elgg.com>
	 * @copyright Curverider Ltd 2008-2009
	 * @link http://elgg.com
	 */

	/**
	 * HTTP Basic Authentication init
	 * 
	 * These parameters are required for the event API, but we won't use them:
 	 * 
	 * @param unknown_type $event
	 * @param unknown_type $object_type
	 * @param unknown_type $object 
	 */
	function http_auth_init()
	{
	    // Register the authentication handler
	    register_pam_handler('http_auth_basic_authenticate');
	}
	
	// Register the initialisation function
	register_elgg_event_handler('init','system','http_auth_init');
	
	/**
	 * HTTP Basic authentication
	 * 
	 * @param mixed $credentials PAM handler specific credentials, not used.
	 * @return boolean
	 */
	function http_auth_basic_authenticate($credentials = null)
    {
	    if (isset($_SERVER['PHP_AUTH_USER']) && $_SERVER['PHP_AUTH_USER'])
        {
            $username = $_SERVER['PHP_AUTH_USER'];
            $password = $_SERVER['PHP_AUTH_PW'];

            if ($user = get_user_by_username($username))
            {
                if ($user->password == $password)
                {
                    // Create the session if not set
                    if (!isloggedin())
                    {
                        return login($user);
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    // Wrong password
                    header('HTTP/1.1 401 Unauthorized');
                    return false;
                }
            }
            else
            {
                // No such user
                header('HTTP/1.1 401 Unauthorized');
                return false;
            }
        }
        else
        {
            return false;
        }
    }
?>