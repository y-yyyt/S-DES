import threading
import time


class SDES:
    """
    S-DES算法实现类
    """

    # 置换盒定义
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]

    # S盒定义
    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2]
    ]

    S1 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3]
    ]

    @staticmethod
    def permute(bits, permutation):
        """执行置换操作"""
        return [bits[i - 1] for i in permutation]

    @staticmethod
    def left_shift(bits, n):
        """循环左移"""
        return bits[n:] + bits[:n]

    @staticmethod
    def xor(bits1, bits2):
        """异或操作"""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    @staticmethod
    def s_box_lookup(bits, s_box):
        """S盒查找"""
        row = (bits[0] << 1) + bits[1]
        col = (bits[2] << 1) + bits[3]
        value = s_box[row][col]
        return [value >> 1 & 1, value & 1]

    @staticmethod
    def string_to_bits(text):
        """将字符串转换为二进制位列表"""
        bits = []
        for char in text:
            byte = ord(char)
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    @staticmethod
    def bits_to_string(bits):
        """将二进制位列表转换为字符串"""
        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                char_code = sum(bit << (7 - j) for j, bit in enumerate(byte))
                chars.append(chr(char_code))
        return ''.join(chars)

    @staticmethod
    def bits_to_hex(bits):
        """将二进制位列表转换为十六进制字符串"""
        result = ""
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                value = sum(bit << (7 - j) for j, bit in enumerate(byte))
                result += f"{value:02X}"
        return result

    @staticmethod
    def hex_to_bits(hex_string):
        """将十六进制字符串转换为二进制位列表"""
        bits = []
        for i in range(0, len(hex_string), 2):
            byte_str = hex_string[i:i + 2]
            if len(byte_str) == 2:
                value = int(byte_str, 16)
                bits.extend([(value >> i) & 1 for i in range(7, -1, -1)])
        return bits

    def generate_keys(self, key):
        """生成子密钥k1和k2"""
        # P10置换
        p10_key = self.permute(key, self.P10)

        # 分割并左移
        left = p10_key[:5]
        right = p10_key[5:]

        # 第一次左移
        left_shift1_left = self.left_shift(left, 1)
        left_shift1_right = self.left_shift(right, 1)

        # 生成k1
        k1 = self.permute(left_shift1_left + left_shift1_right, self.P8)

        # 第二次左移
        left_shift2_left = self.left_shift(left_shift1_left, 2)
        left_shift2_right = self.left_shift(left_shift1_right, 2)

        # 生成k2
        k2 = self.permute(left_shift2_left + left_shift2_right, self.P8)

        return k1, k2

    def f_function(self, right, key):
        """轮函数F"""
        # 扩展置换
        expanded = self.permute(right, self.EP)

        # 与密钥异或
        xor_result = self.xor(expanded, key)

        # S盒替换
        s0_input = xor_result[:4]
        s1_input = xor_result[4:]

        s0_output = self.s_box_lookup(s0_input, self.S0)
        s1_output = self.s_box_lookup(s1_input, self.S1)

        # P4置换
        p4_result = self.permute(s0_output + s1_output, self.P4)

        return p4_result

    def encrypt_block(self, plaintext, key):
        """加密一个8位分组"""
        # 生成子密钥
        k1, k2 = self.generate_keys(key)

        # 初始置换
        ip_result = self.permute(plaintext, self.IP)

        # 第一轮
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k1)
        new_right = self.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮
        f_result = self.f_function(right, k2)
        new_left = self.xor(left, f_result)

        # 最终置换
        ciphertext = self.permute(new_left + right, self.IP_INV)

        return ciphertext

    def decrypt_block(self, ciphertext, key):
        """解密一个8位分组"""
        # 生成子密钥
        k1, k2 = self.generate_keys(key)

        # 初始置换
        ip_result = self.permute(ciphertext, self.IP)

        # 第一轮
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k2)
        new_right = self.xor(left, f_result)

        # 交换
        left, right = right, new_right

        # 第二轮
        f_result = self.f_function(right, k1)
        new_left = self.xor(left, f_result)

        # 最终置换
        plaintext = self.permute(new_left + right, self.IP_INV)

        return plaintext

    def encrypt(self, plaintext_bits, key):
        """加密数据"""
        # 确保数据是8位的倍数
        if len(plaintext_bits) % 8 != 0:
            padding = 8 - (len(plaintext_bits) % 8)
            plaintext_bits.extend([0] * padding)

        ciphertext_bits = []
        for i in range(0, len(plaintext_bits), 8):
            block = plaintext_bits[i:i + 8]
            encrypted_block = self.encrypt_block(block, key)
            ciphertext_bits.extend(encrypted_block)

        return ciphertext_bits

    def decrypt(self, ciphertext_bits, key):
        """解密数据"""
        plaintext_bits = []
        for i in range(0, len(ciphertext_bits), 8):
            block = ciphertext_bits[i:i + 8]
            decrypted_block = self.decrypt_block(block, key)
            plaintext_bits.extend(decrypted_block)

        return plaintext_bits


if __name__ == "__main__":
    main()

