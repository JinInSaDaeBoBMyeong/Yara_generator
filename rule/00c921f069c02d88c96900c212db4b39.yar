
rule BlockRampage
{
	meta:
		author="@Jininsadaebobmyeong"
		filetype="app"
		application_name="BlockRampage"

	strings:
		$permission0 = "android.permission.WRITE_APN_SETTINGS"
		$permission1 = "android.permission.ACCESS_NETWORK_STATE"
		$permission2 = "android.permission.READ_LOGS"
		$permission3 = "android.permission.WAKE_LOCK"
		$permission4 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$permission5 = "android.permission.RECEIVE_SMS"
		$permission6 = "android.permission.READ_SMS"
		$permission7 = "android.permission.READ_CONTACTS"
		$permission8 = "android.permission.WRITE_CONTACTS"
		$permission9 = "android.permission.RESTART_PACKAGES"
		$permission10 = "android.permission.VIBRATE"
		$permission11 = "android.permission.ACCESS_COARSE_LOCATION"
		$permission12 = "android.permission.SEND_SMS"
		$permission13 = "android.permission.DISABLE_KEYGUARD"
		$permission14 = "android.permission.CALL_PHONE"
		$permission15 = "android.permission.WRITE_SMS"
		$permission16 = "android.permission.INTERNET"
		$permission17 = "android.permission.READ_PHONE_STATE"
		$package = "com.spwebgames.blocks"

	condition:
		all of ($permission*) and 
		all of ($package*) and 
		filesize < 594 and 
		(all of ($permission*) or $package)

}
