
rule FlappyDuck
{
	meta:
		author="@Jininsadaebobmyeong"
		filetype="app"
		application_name="FlappyDuck"

	strings:
		$permission0 = "android.permission.ACCESS_NETWORK_STATE"
		$permission1 = "android.permission.ACCESS_COARSE_LOCATION"
		$permission2 = "android.permission.ACCESS_WIFI_STATE"
		$permission3 = "android.permission.WRITE_EXTERNAL_STORAGE"
		$permission4 = "android.permission.GET_ACCOUNTS"
		$permission5 = "android.permission.INTERNET"
		$permission6 = "android.permission.READ_PHONE_STATE"
		$package = "com.botijo.FlappyDuck"

	condition:
		all of ($permission*) and 
		all of ($package*) and 
		filesize < 253 and 
		(all of ($permission*) or $package)

}