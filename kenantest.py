import sys

if __name__ == '__main__':
    dict1 = {'Name': 'Zara', 'Age': 7}
    dict2 = {'Name': 'Kenan', 'Age': 10}
    dict3 = {'Name': 'Hao', 'Age': 99}
    dict4 = {'Name': 'Alice', 'Age': 32}
    dict_list = []
    dict_list.append(dict1)
    dict_list.append(dict2)
    dict_list.append(dict3)
    dict_list.append(dict4)
    x = 0
    while x < len(dict_list):
        if dict_list[x]['Name'] == 'Kenan':
            del dict_list[x]
        x = x + 1

    print dict_list

    name = 'kenan'
    port = '123123123'

    while len(name) < 32:
        name

