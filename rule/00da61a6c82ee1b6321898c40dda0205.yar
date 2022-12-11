
rule Cheat
{
	meta:
		author="@Jininsadaebobmyeong"
		filetype="app"
		application_name="Cheat"

	strings:
		$permission0 = "android.permission.INSTALL_PACKAGES"
		$permission1 = "android.permission.GET_TASKS"
		$permission2 = "android.permission.ACCESS_NETWORK_STATE"
		$permission3 = "android.permission.RECEIVE_BOOT_COMPLETED"
		$permission4 = "android.permission.RECEIVE_SMS"
		$permission5 = "android.permission.CALL_PRIVILEGED"
		$permission6 = "android.permission.READ_CONTACTS"
		$permission7 = "android.permission.READ_SMS"
		$permission8 = "android.permission.SEND_SMS"
		$permission9 = "android.permission.CALL_PHONE"
		$permission10 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$permission11 = "android.permission.DELETE_PACKAGES"
		$permission12 = "android.permission.SYSTEM_ALERT_WINDOW"
		$permission13 = "android.permission.INTERNET"
		$permission14 = "android.permission.READ_PHONE_STATE"
		$package = "com.yandex226.yandex967"

	condition:
		all of ($permission*) and 
		all of ($package*) and 
		filesize < 126 and 
		(all of ($permission*) or $package)

}