
rule XXXvideo
{
	meta:
		author="@Jininsadaebobmyeong"
		filetype="app"
		application_name="XXXvideo"

	strings:
		$permission0 = "android.permission.CAMERA"
		$permission1 = "android.permission.GET_TASKS"
		$permission2 = "android.permission.ACCESS_NETWORK_STATE"
		$permission3 = "android.permission.WAKE_LOCK"
		$permission4 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$permission5 = "android.permission.WRITE_SETTINGS"
		$permission6 = "android.permission.READ_CONTACTS"
		$permission7 = "android.permission.VIBRATE"
		$permission8 = "android.permission.READ_EXTERNAL_STORAGE"
		$permission9 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$permission10 = "android.permission.SYSTEM_ALERT_WINDOW"
		$permission11 = "android.permission.GET_ACCOUNTS"
		$permission12 = "android.permission.INTERNET"
		$permission13 = "android.permission.READ_PHONE_STATE"
		$package = "nsuj.wbbgue.bmzbhnz"

	condition:
		all of ($permission*) and 
		all of ($package*) and 
		filesize < 1060 and 
		(all of ($permission*) or $package)

}