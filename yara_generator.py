import os
import yara
import yara_tools
import Json_maker

def yara_maker(apk_file, size_apk, file_hash):

    sample_name = file_hash
    app_name = apk_file.get_app_name()
    app_name = app_name.replace(" ", "")
    permission = apk_file.get_permissions()

    rule= yara_tools.create_rule(name=app_name)

    rule.set_default_boolean(value='and')

    rule.add_meta(key='author', value='@Jininsadaebobmyeong')
    rule.add_meta(key='filetype', value='app')
    rule.add_meta(key ='application_name', value="{}".format(app_name))



    for ap in range(len(permission)):
        group_name = str('m') + str(ap)
        rule.add_strings(strings=permission[ap], identifier='permission')

    rule.add_condition(condition="filesize < {}".format(size_apk+10))

    generated_rule = rule.build_rule(condition_groups=False)

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

def start(apk_file, size_apk, file_hash):
    if not os.path.isdir('rule'):
        os.mkdir('rule')
    try:
        rule_data = yara_maker(apk_file, size_apk, file_hash)
        file_maker(rule_data[0], rule_data[1])
    except Exception as e:
        print("[+] Failed :", e)
