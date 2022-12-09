import os
import yara
import yara_tools

def yara_maker():
    #hash
    sample_name = '123456789'
    app_name = '앱 이름'
    apk_package = ['com1', 'com2']
    # Permisison example(top 15)
    andro_permission = ['android.permission.GET_INTENT_SENDER_INTENT', 'android.permission.PACKAGE_USAGE_STATS', 'android.permission.WRITE_MEDIA_STORAGE',
                        'android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.WRITE_EXTERNAL_STORAGE', 'android.permission.INTERACT_ACROSS_USERS_FULL',
                        'android.permission.CAPTURE_SECURE_VIDEO_OUTPUT', 'android.permission.SET_PROCESS_LIMIT', 'android.permission.CAPTURE_VIDEO_OUTPUT', 'android.permission.ACCESS_BACKGROUND_LOCATION',
                        'android.permission.RECORD_VIDEO', 'android.permission.READ_CALL_LOG', 'android.permission.CAPTURE_AUDIO_HOTWORD', 'android.permission.READ_EXTERNAL_STORAGE']

    #import module
    rule= yara_tools.create_rule(name=sample_name)
    rule.add_import(name='androguard')
    rule.set_default_boolean(value='and')

    #rule meta data
    rule.add_meta(key='author', value='@Jininsadaebobmyeong')
    rule.add_meta(key = 'application name', value=app_name)

    rule.add_condition(condition="filesize < 100000")

    #Permission Rule
    for i in range(len(andro_permission)):
        permission_rule = 'androguard.permission("{}")'.format(andro_permission[i])
        rule.add_condition(condition = permission_rule)
    #package
    for ap in range(len(apk_package)):
        apk_package_rule = 'androguard.package_name("{}")'.format(apk_package[ap])
        rule.add_condition(condition=apk_package_rule)
    #app name
    app_name_rule = 'androguard.app_name("{}")'.format(app_name)
    rule.add_condition(condition=app_name_rule)

    generated_rule = rule.build_rule()

    try:
        print(generated_rule)
        print("[+] SUCCESS: IT WORKED!")
        return sample_name, generated_rule
    except Exception as e:
        print("[+] Failed :", e)

#file make
def file_maker(file_name, rule_data):
    file_path = 'rule/{}.yar'.format(file_name)
    with open(file_path, 'w') as f:
        f.write(rule_data)
    print("[+] File Make Success!")
if __name__=="__main__":
    if not os.path.isdir('rule'):
        os.mkdir('rule')
    try:
        rule_data = yara_maker()
        file_maker(rule_data[0], rule_data[1])
    except Exception as e:
        print("[+] Failed :", e)
