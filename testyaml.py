#!/usr/bin/python3
import yaml
import pprint  # 导入漂亮打印模块，让输出的字典格式更易读

def test_load():
    try:
        # 1. 打开并读取本地的 selfbuilt.yaml 文件
        with open("./selfbuilt.yaml", "r", encoding="utf-8") as f:
            yaml_content = f.read()
        
        # 2. 使用 safe_load 解析
        parsed_data = yaml.safe_load(yaml_content)
        
        # 3. 打印解析后的 Python 对象类型和具体内容
        print(f"解析成功！解析后的根数据类型是: {type(parsed_data)}\n")
        print("--- 解析后的详细数据结构如下 ---")
        
        # 使用 pprint.pprint 可以把嵌套的字典和列表格式化对齐，非常清晰
        pprint.pprint(parsed_data)
        
    except FileNotFoundError:
        print("错误：未在当前目录下找到 ./selfbuilt.yaml 文件，请检查路径。")
    except yaml.YAMLError as exc:
        print(f"YAML 语法错误，解析失败：\n{exc}")

if __name__ == "__main__":
    test_load()
