import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
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


class SDESGUI:
    """S-DES图形用户界面"""

    def __init__(self):
        self.sdes = SDES()
        self.setup_gui()

        # 暴力破解相关
        self.brute_force_running = False

    def setup_gui(self):
        """设置GUI界面"""
        self.root = tk.Tk()
        self.root.title("S-DES加解密系统")
        self.root.geometry("800x700")

        # 创建标签页
        notebook = ttk.Notebook(self.root)

        # 第1关：基本测试
        tab1 = ttk.Frame(notebook)
        self.setup_basic_test_tab(tab1)

        # 第3关：扩展功能
        tab3 = ttk.Frame(notebook)
        self.setup_extension_tab(tab3)

        # 第4关：暴力破解
        tab4 = ttk.Frame(notebook)
        self.setup_brute_force_tab(tab4)

        # 第5关：封闭测试
        tab5 = ttk.Frame(notebook)
        self.setup_analysis_tab(tab5)

        notebook.add(tab1, text="基本测试")
        notebook.add(tab3, text="扩展功能")
        notebook.add(tab4, text="暴力破解")
        notebook.add(tab5, text="封闭测试")
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

    def setup_basic_test_tab(self, parent):
        """设置基本测试标签页"""
        # 密钥输入
        tk.Label(parent, text="10位密钥 (二进制):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.key_entry = tk.Entry(parent, width=20)
        self.key_entry.grid(row=0, column=1, padx=5, pady=5)

        # 明文输入
        tk.Label(parent, text="8位明文 (二进制):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.plaintext_entry = tk.Entry(parent, width=20)
        self.plaintext_entry.grid(row=1, column=1, padx=5, pady=5)

        # 加密按钮
        encrypt_btn = tk.Button(parent, text="加密", command=self.encrypt_basic)
        encrypt_btn.grid(row=2, column=0, padx=5, pady=10)

        # 解密按钮
        decrypt_btn = tk.Button(parent, text="解密", command=self.decrypt_basic)
        decrypt_btn.grid(row=2, column=1, padx=5, pady=10)

        # 结果显示
        tk.Label(parent, text="结果:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.result_text = scrolledtext.ScrolledText(parent, width=50, height=10)
        self.result_text.grid(row=4, column=0, columnspan=2, padx=5, pady=5)

        # 示例按钮
        example_btn = tk.Button(parent, text="填充示例", command=self.fill_example)
        example_btn.grid(row=5, column=0, columnspan=2, padx=5, pady=10)

    def setup_extension_tab(self, parent):
        """设置扩展功能标签页"""
        # 密钥输入
        tk.Label(parent, text="10位密钥 (二进制):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.ext_key_entry = tk.Entry(parent, width=20)
        self.ext_key_entry.grid(row=0, column=1, padx=5, pady=5)

        # 文本输入
        tk.Label(parent, text="文本:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.text_entry = scrolledtext.ScrolledText(parent, width=50, height=5)
        self.text_entry.grid(row=2, column=0, columnspan=2, padx=5, pady=5)

        # 加密按钮
        encrypt_btn = tk.Button(parent, text="加密文本", command=self.encrypt_text)
        encrypt_btn.grid(row=3, column=0, padx=5, pady=10)

        # 解密按钮
        decrypt_btn = tk.Button(parent, text="解密文本", command=self.decrypt_text)
        decrypt_btn.grid(row=3, column=1, padx=5, pady=10)

        # 结果显示
        tk.Label(parent, text="结果:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.ext_result_text = scrolledtext.ScrolledText(parent, width=50, height=10)
        self.ext_result_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def setup_brute_force_tab(self, parent):
        """设置暴力破解标签页"""
        # 明密文对输入
        tk.Label(parent, text="已知明文 (二进制):").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        self.known_plaintext = tk.Entry(parent, width=20)
        self.known_plaintext.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(parent, text="已知密文 (二进制):").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        self.known_ciphertext = tk.Entry(parent, width=20)
        self.known_ciphertext.grid(row=1, column=1, padx=5, pady=5)

        # 暴力破解按钮
        brute_btn = tk.Button(parent, text="开始暴力破解", command=self.start_brute_force)
        brute_btn.grid(row=2, column=0, padx=5, pady=10)

        stop_btn = tk.Button(parent, text="停止破解", command=self.stop_brute_force)
        stop_btn.grid(row=2, column=1, padx=5, pady=10)

        # 进度显示
        tk.Label(parent, text="进度:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(parent, variable=self.progress_var, maximum=1024)
        self.progress_bar.grid(row=3, column=1, sticky='ew', padx=5, pady=5)

        # 结果显示
        tk.Label(parent, text="破解结果:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        self.brute_result_text = scrolledtext.ScrolledText(parent, width=50, height=10)
        self.brute_result_text.grid(row=5, column=0, columnspan=2, padx=5, pady=5)

    def setup_analysis_tab(self, parent):
        """设置分析标签页"""
        # 分析按钮
        analyze_btn = tk.Button(parent, text="分析密钥冲突", command=self.analyze_key_conflicts)
        analyze_btn.grid(row=0, column=0, padx=5, pady=10)

        # 结果显示
        self.analysis_text = scrolledtext.ScrolledText(parent, width=80, height=20)
        self.analysis_text.grid(row=1, column=0, padx=5, pady=5)

    def string_to_bit_list(self, s):
        """将二进制字符串转换为位列表"""
        return [int(bit) for bit in s]

    def bit_list_to_string(self, bits):
        """将位列表转换为二进制字符串"""
        return ''.join(str(bit) for bit in bits)

    def fill_example(self):
        """填充示例数据"""
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, "1010000010")
        self.plaintext_entry.delete(0, tk.END)
        self.plaintext_entry.insert(0, "01110010")

    def encrypt_basic(self):
        """基本加密"""
        try:
            key_str = self.key_entry.get()
            plaintext_str = self.plaintext_entry.get()

            if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
                messagebox.showerror("错误", "密钥必须是10位二进制数")
                return

            if len(plaintext_str) != 8 or not all(bit in '01' for bit in plaintext_str):
                messagebox.showerror("错误", "明文必须是8位二进制数")
                return

            key = self.string_to_bit_list(key_str)
            plaintext = self.string_to_bit_list(plaintext_str)

            ciphertext = self.sdes.encrypt_block(plaintext, key)
            ciphertext_str = self.bit_list_to_string(ciphertext)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"明文: {plaintext_str}\n")
            self.result_text.insert(tk.END, f"密钥: {key_str}\n")
            self.result_text.insert(tk.END, f"密文: {ciphertext_str}\n")

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def decrypt_basic(self):
        """基本解密"""
        try:
            key_str = self.key_entry.get()
            ciphertext_str = self.plaintext_entry.get()  # 重用明文输入框

            if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
                messagebox.showerror("错误", "密钥必须是10位二进制数")
                return

            if len(ciphertext_str) != 8 or not all(bit in '01' for bit in ciphertext_str):
                messagebox.showerror("错误", "密文必须是8位二进制数")
                return

            key = self.string_to_bit_list(key_str)
            ciphertext = self.string_to_bit_list(ciphertext_str)

            plaintext = self.sdes.decrypt_block(ciphertext, key)
            plaintext_str = self.bit_list_to_string(plaintext)

            self.result_text.delete(1.0, tk.END)
            self.result_text.insert(tk.END, f"密文: {ciphertext_str}\n")
            self.result_text.insert(tk.END, f"密钥: {key_str}\n")
            self.result_text.insert(tk.END, f"明文: {plaintext_str}\n")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def encrypt_text(self):
        """加密文本"""
        try:
            key_str = self.ext_key_entry.get()
            text = self.text_entry.get(1.0, tk.END).strip()

            if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
                messagebox.showerror("错误", "密钥必须是10位二进制数")
                return

            key = self.string_to_bit_list(key_str)
            text_bits = self.sdes.string_to_bits(text)

            ciphertext_bits = self.sdes.encrypt(text_bits, key)
            ciphertext_hex = self.sdes.bits_to_hex(ciphertext_bits)
            ciphertext_str = self.sdes.bits_to_string(ciphertext_bits)

            self.ext_result_text.delete(1.0, tk.END)
            self.ext_result_text.insert(tk.END, f"原文: {text}\n")
            self.ext_result_text.insert(tk.END, f"密钥: {key_str}\n")
            self.ext_result_text.insert(tk.END, f"密文(十六进制): {ciphertext_hex}\n")
            self.ext_result_text.insert(tk.END, f"密文(字符串): {ciphertext_str}\n")

        except Exception as e:
            messagebox.showerror("错误", f"加密失败: {str(e)}")

    def decrypt_text(self):
        """解密文本"""
        try:
            key_str = self.ext_key_entry.get()
            text = self.text_entry.get(1.0, tk.END).strip()

            if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
                messagebox.showerror("错误", "密钥必须是10位二进制数")
                return

            key = self.string_to_bit_list(key_str)

            # 尝试作为十六进制解析，如果不是则作为字符串处理
            try:
                ciphertext_bits = self.sdes.hex_to_bits(text)
            except:
                ciphertext_bits = self.sdes.string_to_bits(text)

            plaintext_bits = self.sdes.decrypt(ciphertext_bits, key)
            plaintext_str = self.sdes.bits_to_string(plaintext_bits)

            self.ext_result_text.delete(1.0, tk.END)
            self.ext_result_text.insert(tk.END, f"密文: {text}\n")
            self.ext_result_text.insert(tk.END, f"密钥: {key_str}\n")
            self.ext_result_text.insert(tk.END, f"明文: {plaintext_str}\n")

        except Exception as e:
            messagebox.showerror("错误", f"解密失败: {str(e)}")

    def brute_force_worker(self):
        """暴力破解工作线程"""
        try:
            plaintext_str = self.known_plaintext.get()
            ciphertext_str = self.known_ciphertext.get()

            if len(plaintext_str) != 8 or not all(bit in '01' for bit in plaintext_str):
                self.brute_result_text.insert(tk.END, "错误: 明文必须是8位二进制数\n")
                return

            if len(ciphertext_str) != 8 or not all(bit in '01' for bit in ciphertext_str):
                self.brute_result_text.insert(tk.END, "错误: 密文必须是8位二进制数\n")
                return

            plaintext = self.string_to_bit_list(plaintext_str)
            target_ciphertext = self.string_to_bit_list(ciphertext_str)

            start_time = time.time()
            found_keys = []

            # 遍历所有可能的10位密钥
            for key_int in range(1024):
                if not self.brute_force_running:
                    break

                key = [(key_int >> i) & 1 for i in range(9, -1, -1)]

                # 尝试加密
                try:
                    encrypted = self.sdes.encrypt_block(plaintext, key)
                    if encrypted == target_ciphertext:
                        key_str = self.bit_list_to_string(key)
                        found_keys.append(key_str)
                        self.brute_result_text.insert(tk.END, f"找到密钥: {key_str}\n")
                        self.brute_result_text.see(tk.END)

                except Exception:
                    continue

                # 更新进度
                self.progress_var.set(key_int + 1)

            end_time = time.time()
            elapsed_time = end_time - start_time

            self.brute_result_text.insert(tk.END, f"\n破解完成! 用时: {elapsed_time:.2f}秒\n")
            if found_keys:
                self.brute_result_text.insert(tk.END, f"共找到 {len(found_keys)} 个可能的密钥\n")
            else:
                self.brute_result_text.insert(tk.END, "未找到匹配的密钥\n")

        except Exception as e:
            self.brute_result_text.insert(tk.END, f"错误: {str(e)}\n")
        finally:
            self.brute_force_running = False

    def start_brute_force(self):
        """开始暴力破解"""
        if self.brute_force_running:
            messagebox.showwarning("警告", "暴力破解正在进行中")
            return

        self.brute_force_running = True
        self.brute_result_text.delete(1.0, tk.END)
        self.brute_result_text.insert(tk.END, "开始暴力破解...\n")

        # 在新线程中运行暴力破解
        thread = threading.Thread(target=self.brute_force_worker)
        thread.daemon = True
        thread.start()

    def stop_brute_force(self):
        """停止暴力破解"""
        self.brute_force_running = False
        self.brute_result_text.insert(tk.END, "暴力破解已停止\n")

    def analyze_key_conflicts(self):
        """分析密钥冲突"""
        try:
            self.analysis_text.delete(1.0, tk.END)
            self.analysis_text.insert(tk.END, "开始分析密钥冲突...\n")
            self.analysis_text.update()

            # 测试随机明文
            import random
            test_plaintext = [random.randint(0, 1) for _ in range(8)]
            plaintext_str = self.bit_list_to_string(test_plaintext)

            ciphertext_to_keys = {}
            key_conflicts = []

            start_time = time.time()

            # 遍历所有密钥
            for key_int in range(1024):
                key = [(key_int >> i) & 1 for i in range(9, -1, -1)]
                key_str = self.bit_list_to_string(key)

                try:
                    ciphertext = self.sdes.encrypt_block(test_plaintext, key)
                    ciphertext_str = self.bit_list_to_string(ciphertext)

                    if ciphertext_str in ciphertext_to_keys:
                        # 发现冲突
                        existing_key = ciphertext_to_keys[ciphertext_str]
                        key_conflicts.append((existing_key, key_str, ciphertext_str))
                    else:
                        ciphertext_to_keys[ciphertext_str] = key_str

                except Exception:
                    continue

            end_time = time.time()
            elapsed_time = end_time - start_time

            self.analysis_text.insert(tk.END, f"\n分析完成! 用时: {elapsed_time:.2f}秒\n")
            self.analysis_text.insert(tk.END, f"测试明文: {plaintext_str}\n")
            self.analysis_text.insert(tk.END, f"不同密文数量: {len(ciphertext_to_keys)}\n")
            self.analysis_text.insert(tk.END, f"密钥冲突数量: {len(key_conflicts)}\n\n")

            if key_conflicts:
                self.analysis_text.insert(tk.END, "发现的密钥冲突:\n")
                for i, (key1, key2, ciphertext) in enumerate(key_conflicts[:10]):  # 只显示前10个
                    self.analysis_text.insert(tk.END,
                                              f"冲突 {i + 1}: 密钥 {key1} 和 {key2} 产生相同密文 {ciphertext}\n")

                if len(key_conflicts) > 10:
                    self.analysis_text.insert(tk.END, f"... 还有 {len(key_conflicts) - 10} 个冲突未显示\n")
            else:
                self.analysis_text.insert(tk.END, "未发现密钥冲突\n")

        except Exception as e:
            self.analysis_text.insert(tk.END, f"分析失败: {str(e)}\n")

    def run(self):
        """运行GUI"""
        self.root.mainloop()


def main():
    """主函数"""
    # 创建并运行GUI
    gui = SDESGUI()
    gui.run()


if __name__ == "__main__":
    main()
