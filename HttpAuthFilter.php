<?php
/**
 * HttpAuthFilter class file.
 *
 * @license BSD
 */

/**
 * HttpAuthFilter performs authorization checks using http authentication
 *
 * By enabling this filter, controller actions can be limited to a couple of users.
 * It is very simple, supply a list of usernames and passwords and the controller actions
 * will be restricted to only those. Nothing fancy, it just keeps out users.
 *
 * To specify the authorized users specify the 'users' property of the filter
 * Example:
 * <pre>
 * public function filters()
 * {
 *     return array(
 *         array(
 *             'HttpAuthFilter',
 *             'users'=>array('admin'=>'admin'),
 *             'realm'=>'Admin section',
 *         ),
 *     );
 * }
 * </pre>
 * The default section for the users property is 'admin'=>'admin'. Change it!
 *
 * in php/cgi context $_SERVER['PHP_AUTH_USER'] and $_SERVER['PHP_AUTH_PW'] are not set.
 * the following rule uses the apache module mod_rewrite to store the http authorization data in the
 * environment variable 'HTTP_AUTHORIZATION', depending on your server it will be accessible as
 * $_SERVER['HTTP_AUTHORIZATION'] or $_SERVER['REDIRECT_HTTP_AUTHORIZATION']:
 * <pre>
 * <IfModule mod_rewrite.c>
 *     RewriteEngine on
 *     RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]
 * </IfModule>
 * </pre>
 * set cgiWorkaroundEnvironmentVar to 'HTTP_AUTHORIZATION' or 'REDIRECT_HTTP_AUTHORIZATION'.
 */
class HttpAuthFilter extends CFilter
{
	/**
	 * @var array list of authorized users/passwords
	 */
	public $users=array('admin'=>'admin',);

	/**
	 * @var string authentication realm
	 */
	public $realm='Authentication needed';

	/**
	 * @var mixed false or string, name of environment variable where http authorization header is stored in php/cgi context.
	 */
	public $cgiWorkaroundEnvironmentVar=false;

	/**
	 * Performs the pre-action filtering.
	 * @param CFilterChain the filter chain that the filter is on.
	 * @return boolean whether the filtering process should continue and the action
	 * should be executed.
	 */
	protected function preFilter($filterChain)
	{
		// get auth data if cgiWorkaroundEnvironmentVar ist set
		if ( $this->cgiWorkaroundEnvironmentVar && isset($_SERVER[ $this->cgiWorkaroundEnvironmentVar ]) )
		{
			list($_SERVER['PHP_AUTH_USER'], $_SERVER['PHP_AUTH_PW']) = explode(':' , base64_decode(substr($_SERVER[ $this->cgiWorkaroundEnvironmentVar ], 6)));
		}

		if (isset($_SERVER['PHP_AUTH_USER']) && isset($_SERVER['PHP_AUTH_PW']))
		{
			$username=$_SERVER['PHP_AUTH_USER'];
			$password=$_SERVER['PHP_AUTH_PW'];

			if(isset($this->users[$username]) && $this->users[$username]===$password)
			{
				return true;
			}
		}
		header("WWW-Authenticate: Basic realm=\"".$this->realm."\"");
		throw new CHttpException(401,Yii::t('yii','You are not authorized to perform this action.'));
	}
}
