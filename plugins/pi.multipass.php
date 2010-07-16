<?php

$plugin_info = array(
  'pi_name' => 'Tender MultiPass',
  'pi_version' =>'1.0',
  'pi_author' =>'ENTP',
  'pi_author_url' => 'https://help.tenderapp.com/faqs/setup-installation/multipass',
  'pi_description' => 'Creates a Tender MultiPass anchor link',
  'pi_usage' => Multipass::usage()
);

/**
 * MultiPass is a plugin for ExpressionEngine that generates the anchor element, 
 * with necessary href to let users sign on to Tender from ExpressionEngine
 *
 * @package MultiPass
 */
class Multipass {
	
	/**
	 * The returned HTML to the template parser
	 *
	 * @var string
	 */
	public $return_data;

	/**
	 * The MultiPass object constructor which sets the return data
	 * so no extra function call is made.
	 */
	public function Multipass()
	{
		global $TMPL, $SESS, $LANG;
		
		$tender_params = array();
		
		//Checks to see if a tender link was even entered
		if (!$link = str_replace("http://", "", $TMPL->fetch_param('link')))
		{
			$this->return_data = "You haven't entered your Tender App URL";
			return;
		}
				
		if (!$TMPL->fetch_param('key'))
		{
			$this->return_data = "You haven't entered your Tender Key";
			return;
		}
		
		if (!$TMPL->fetch_param('sso_key'))
		{
			$this->return_data = "You haven't entered your SSO API Key";
			return;
		}
		
		//If the text parameter is set, use that, if not: use support.
		$link_text = $TMPL->fetch_param('text') ? $TMPL->fetch_param('text') : "Support";
		
		// Checks to see if the user is logged in
		if ($SESS->userdata['member_id'] == 0 || $SESS->userdata['member_id'] == "")
		{
			$this->return_data =  '<a href="http://'.$link.'">'.$link_text.'</a>';
			return;
		}
		
		//Is the user's email setup?
		if (!$email = $SESS->userdata['email'])
		{
			$this->return_data = "You must enter your email address for support";
			return;
		}
		
		//Now we setup the params with reasonable defaults
		$tender_params = array(
			'unique_id' => $SESS->userdata['member_id'],
			'name'      => $SESS->userdata['screen_name'],
			'expires'   => date("Y-m-d H:i:s", strtotime("+30 minutes")),
			'email'     => $email,
			'trusted'   => true,
		);

		$this->return_data = '<a href="http://'. $link  . $this->getTenderLink($tender_params).'">'.$link_text.'</a>';
	}
	
	/**
	 * Generates a Tender API link, accepting parameters and doing all the
	 * hashing, security-ing, and modify-ing.
	 *
	 * @param array $params User information 
	 * @return string Tender MultiPass link
	 */
	private function getTenderLink($params)
	{
		global $TMPL;

		$account_key = $TMPL->fetch_param['key']; //Tender Key
		$api_key     = $TMPL->fetch_param['sso_key']; //Tender API Key

		$hash= hash('sha1', $api_key . $account_key, true);
		
		$saltedHash = substr($hash,0,16);
		
		$iv= "OpenSSL for Ruby";

		$data = json_encode($params);
		
		for ($i = 0; $i < 16; $i++)
		{
		    $data[$i] = $data[$i] ^ $iv[$i];
		}

		$pad = 16 - (strlen($data) % 16);
		$data = $data . str_repeat(chr($pad), $pad);
		$cipher = mcrypt_module_open(MCRYPT_RIJNDAEL_128,'','cbc','');
		mcrypt_generic_init($cipher, $saltedHash, $iv);
		$encryptedData = mcrypt_generic($cipher,$data);
		mcrypt_generic_deinit($cipher);

		$multipass = urlencode(base64_encode($encryptedData));
		
		return "?sso={$multipass}";
	}
	
	/**
	 * These are the instructions for the Plugin
	 *
	 * @return string	
	 */
	public function usage()
	{
		ob_start();
	?>
	What is Tender's MultiPass Single-Sign on?

	When you build a website with [CMS], it already comes with a user registration system. Tender compliments your application, product or marketing site by being able to share this registration systems information.

	With MultiPass Single Sign On you don't need user's to re-register with Tender, who wants to do that? Terrible people. That's whom.

	With MultiPass we pass all the user information as securely as possible over a simple hyperlink. 

	This plugin goes one step further and makes sure you don't have to do any of the weird encryption and crazy programming to secure the info. All you need to know are three simple things: 

	1. Your Tender url (e.g. http://help.tender.com)
	2. Your SSO Key
	3. Your Tender Key
	
	How fantastic is that? This plugin will automatically generate that anchor element for you. It looks something like this:
	
	<a href="(the generated url)">Support</a>
	
	Enabling MultiPass SSO

	In order to use this plugin you need to enable MultiPass on your Tender application. Here's how:

	1. Login to your Tender app so you see your dashboard
	2. Click on the Site Settings nav item
	3. Scroll down to the bottom of the page
	4. Where it says "MultiPass Single Sign On" click on "Enabled".
	5. Copy and paste your SSO API key and your site key, make sure you keep them separate and you know which is which. 

	With those three pieces of information, this plugin will automatically generate your Tender link.
	
	3. Finally you can setup the plugin like this in your EE template:

	{exp:multipass sso_key="your_sso_key" key="your_tender_key" link="yourtenderurl.com"}
	
	You can also add optional parameters: 
	
	text="Support" You can change the text of the link
	
	Where "link" is the link to your Tender app. My Tender app, for example, is called MultiPass. Therefore, my link is "http://multipass.tenderapp.com". You don't even have to add the http:// if you don't want to. 
	
	It works perfectly well if you've setup Tender with your own domain. So use that link instead if you'd like (e.g. help.mydomain.com).
	
	Just so you know, it's an incredibly long and ugly URL. It doesn't look pretty, but it works so well. This just means your data is as secure as it can possibly be.
	<?php
	
		$buffer = ob_get_contents();
	
		ob_end_clean();
	
		return $buffer;
	}
}