import random


def generate_random_str(randomlength=16):
    """
  生成一个指定长度的随机字符串
  """
    random_str = ''
    base_str = 'ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghigklmnopqrstuvwxyz0123456789'
    length = len(base_str) - 1
    for i in range(randomlength):
        random_str += base_str[random.randint(0, length)]
    return random_str


def generate_random_number(num_digits=5):
    if num_digits <= 0:
        raise ValueError("Number of digits must be a positive integer.")

    # 生成随机数的范围
    lower_bound = 10 ** (num_digits - 1)
    upper_bound = 10 ** num_digits - 1

    # 生成随机整数
    random_number = random.randint(lower_bound, upper_bound)

    # 转换为字符串格式
    random_number_str = str(random_number)

    return random_number_str
