<?php

namespace Useragent;

class Bot
{
	// Check if is a known bot
	public static function check()
	{
		if (!isset($_SERVER['HTTP_USER_AGENT'])) {
			$_SERVER['HTTP_USER_AGENT'] = '';
		}

		$bots = array(
			// Googlebot
			// http://support.google.com/webmasters/bin/answer.py?hl=en&answer=1061943
			'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
			'Googlebot/2.1 (+http://www.google.com/bot.html)',
			'Googlebot-News',
			'Googlebot-Image/1.0',
			'Googlebot-Video/1.0',
			//'(compatible; Googlebot-Mobile/2.1; +http://www.google.com/bot.html)',
			//'(compatible; Mediapartners-Google/2.1; +http://www.google.com/bot.html)',
			'Mediapartners-Google',
			'AdsBot-Google (+http://www.google.com/adsbot.html)',
		);

		// Check for a complete match
		if (in_array($_SERVER['HTTP_USER_AGENT'], $bots)) {
			return true;
		}

		// Check for incomplete match (possibly covers other bots, and the Google Mobile Bots)
		if (strpos($_SERVER['HTTP_USER_AGENT'], 'bot.html') !== false) {
			return true;
		}

		if (strpos($_SERVER['HTTP_USER_AGENT'], 'AdsBot') !== false) {
			return true;
		}


		// Check Known Google IP Ranges
		if (empty($_SERVER['REMOTE_ADDR'])) {
			return false;
		}

		$google_ips = array(
			// http://www.fixedorbit.com/cgi-bin/cgirange.exe?ASN=15169
			'8.8.4.0/24',
			'8.8.8.0/24',
			'64.233.160.0/19',
			'66.102.0.0/20',
			'66.249.64.0/19',
			'72.14.192.0/18',
			'74.125.0.0/16',
			'113.197.105.0/24',
			'173.194.0.0/16',
			'209.85.128.0/17',
			'216.239.32.0/19',

			// http://www.fixedorbit.com/cgi-bin/cgirange.exe?ASN=36040
			'208.117.232.0/24',
			'208.117.233.0/24'
		);
		
		return static::check_cidr_array($_SERVER['REMOTE_ADDR'], $google_ips);
	}


	/**
	 * check_cidr_array 
	 * 
	 * @param mixed $ip 
	 * @param mixed $cidrs 
	 * @static
	 * @access protected
	 * @return void
	 */
	protected static function check_cidr_array($ip, $cidrs)
	{
		// Allows you to use null or false for proplogin.servers/clients to override an array in the admin config
		if ( ! is_array($cidrs)) {
			return false;
		}

		$cidrs = static::hostnames_to_ips($cidrs);

		foreach ($cidrs as $cidr) {
			if (static::check_cidr($ip, $cidr)) {
				return true;
			}
		}

		// no cidrs matched so return false
		return false;
	}

	/**
	 * hostnames_to_ips 
	 * 
	 * @param mixed $hosts Hostnames or IP Addresses
	 * @static
	 * @access protected
	 * @return void
	 */
	protected static function hostnames_to_ips($hosts)
	{
		foreach ($hosts as $key => $host) {
			if ( ! preg_match('~^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$~', $host)) {
				unset($hosts[$key]);

				$records = dns_get_record($host, DNS_A);

				foreach ($records as $record) {
					$hosts[] = $record['ip'];
				}
			}
		}

		return $hosts;
	}

	/**
	 * check_cidr 
	 * 
	 * @param mixed $ip 
	 * @param mixed $cidr 
	 * @static
	 * @access protected
	 * @return void
	 */
	protected static function check_cidr($ip, $cidr)
	{
		if (strpos($cidr, '/') === false) {
			$cidr .= '/32';
		}

		list($net, $mask) = explode('/', $cidr);

		$ip_net = ip2long($net);
		$ip_mask = ~((1 << (32 - $mask)) -1);

		$ip_ip = ip2long($ip);
		$ip_ip_net = $ip_ip & $ip_mask;

		return $ip_ip_net == $ip_net;
	}
	
}
