import sys
import time
from typing import List

from PyQt5 import QtCore, QtGui, QtWidgets


class SDES:
    """
    S-DES算法实现类
    （从 Tk 版本迁移，保持接口一致）
    """

    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
    EP = [4, 1, 2, 3, 2, 3, 4, 1]
    P4 = [2, 4, 3, 1]

    S0 = [
        [1, 0, 3, 2],
        [3, 2, 1, 0],
        [0, 2, 1, 3],
        [3, 1, 0, 2],
    ]

    S1 = [
        [0, 1, 2, 3],
        [2, 3, 1, 0],
        [3, 0, 1, 2],
        [2, 1, 0, 3],
    ]

    @staticmethod
    def permute(bits: List[int], permutation: List[int]) -> List[int]:
        return [bits[i - 1] for i in permutation]

    @staticmethod
    def left_shift(bits: List[int], n: int) -> List[int]:
        return bits[n:] + bits[:n]

    @staticmethod
    def xor(bits1: List[int], bits2: List[int]) -> List[int]:
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    @staticmethod
    def s_box_lookup(bits: List[int], s_box: List[List[int]]) -> List[int]:
        row = (bits[0] << 1) + bits[1]
        col = (bits[2] << 1) + bits[3]
        value = s_box[row][col]
        return [value >> 1 & 1, value & 1]

    @staticmethod
    def string_to_bits(text: str) -> List[int]:
        bits: List[int] = []
        for char in text:
            byte = ord(char)
            bits.extend([(byte >> i) & 1 for i in range(7, -1, -1)])
        return bits

    @staticmethod
    def bits_to_string(bits: List[int]) -> str:
        chars: List[str] = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                char_code = sum(bit << (7 - j) for j, bit in enumerate(byte))
                chars.append(chr(char_code))
        return ''.join(chars)

    @staticmethod
    def bits_to_hex(bits: List[int]) -> str:
        result = ""
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            if len(byte) == 8:
                value = sum(bit << (7 - j) for j, bit in enumerate(byte))
                result += f"{value:02X}"
        return result

    @staticmethod
    def hex_to_bits(hex_string: str) -> List[int]:
        bits: List[int] = []
        for i in range(0, len(hex_string), 2):
            byte_str = hex_string[i:i + 2]
            if len(byte_str) == 2:
                value = int(byte_str, 16)
                bits.extend([(value >> i) & 1 for i in range(7, -1, -1)])
        return bits

    def generate_keys(self, key: List[int]):
        p10_key = self.permute(key, self.P10)
        left = p10_key[:5]
        right = p10_key[5:]
        left_shift1_left = self.left_shift(left, 1)
        left_shift1_right = self.left_shift(right, 1)
        k1 = self.permute(left_shift1_left + left_shift1_right, self.P8)
        left_shift2_left = self.left_shift(left_shift1_left, 2)
        left_shift2_right = self.left_shift(left_shift1_right, 2)
        k2 = self.permute(left_shift2_left + left_shift2_right, self.P8)
        return k1, k2

    def f_function(self, right: List[int], key: List[int]) -> List[int]:
        expanded = self.permute(right, self.EP)
        xor_result = self.xor(expanded, key)
        s0_input = xor_result[:4]
        s1_input = xor_result[4:]
        s0_output = self.s_box_lookup(s0_input, self.S0)
        s1_output = self.s_box_lookup(s1_input, self.S1)
        p4_result = self.permute(s0_output + s1_output, self.P4)
        return p4_result

    def encrypt_block(self, plaintext: List[int], key: List[int]) -> List[int]:
        k1, k2 = self.generate_keys(key)
        ip_result = self.permute(plaintext, self.IP)
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k1)
        new_right = self.xor(left, f_result)
        left, right = right, new_right
        f_result = self.f_function(right, k2)
        new_left = self.xor(left, f_result)
        ciphertext = self.permute(new_left + right, self.IP_INV)
        return ciphertext

    def decrypt_block(self, ciphertext: List[int], key: List[int]) -> List[int]:
        k1, k2 = self.generate_keys(key)
        ip_result = self.permute(ciphertext, self.IP)
        left = ip_result[:4]
        right = ip_result[4:]
        f_result = self.f_function(right, k2)
        new_right = self.xor(left, f_result)
        left, right = right, new_right
        f_result = self.f_function(right, k1)
        new_left = self.xor(left, f_result)
        plaintext = self.permute(new_left + right, self.IP_INV)
        return plaintext

    def encrypt(self, plaintext_bits: List[int], key: List[int]) -> List[int]:
        if len(plaintext_bits) % 8 != 0:
            padding = 8 - (len(plaintext_bits) % 8)
            plaintext_bits = plaintext_bits + [0] * padding
        ciphertext_bits: List[int] = []
        for i in range(0, len(plaintext_bits), 8):
            block = plaintext_bits[i:i + 8]
            encrypted_block = self.encrypt_block(block, key)
            ciphertext_bits.extend(encrypted_block)
        return ciphertext_bits

    def decrypt(self, ciphertext_bits: List[int], key: List[int]) -> List[int]:
        plaintext_bits: List[int] = []
        for i in range(0, len(ciphertext_bits), 8):
            block = ciphertext_bits[i:i + 8]
            decrypted_block = self.decrypt_block(block, key)
            plaintext_bits.extend(decrypted_block)
        return plaintext_bits


def string_to_bit_list(s: str) -> List[int]:
    return [int(bit) for bit in s]


def bit_list_to_string(bits: List[int]) -> str:
    return ''.join(str(bit) for bit in bits)


class BruteForceWorker(QtCore.QObject):
    progressChanged = QtCore.pyqtSignal(int)
    messageAppended = QtCore.pyqtSignal(str)
    finished = QtCore.pyqtSignal()

    def __init__(self, sdes: SDES, plaintext_str: str, ciphertext_str: str):
        super().__init__()
        self._sdes = sdes
        self._plaintext_str = plaintext_str
        self._ciphertext_str = ciphertext_str
        self._running = True

    @QtCore.pyqtSlot()
    def run(self):
        try:
            if len(self._plaintext_str) != 8 or not all(bit in '01' for bit in self._plaintext_str):
                self.messageAppended.emit("错误: 明文必须是8位二进制数\n")
                return
            if len(self._ciphertext_str) != 8 or not all(bit in '01' for bit in self._ciphertext_str):
                self.messageAppended.emit("错误: 密文必须是8位二进制数\n")
                return

            plaintext = string_to_bit_list(self._plaintext_str)
            target_ciphertext = string_to_bit_list(self._ciphertext_str)

            start_time = time.time()
            found_count = 0

            for key_int in range(1024):
                if not self._running:
                    break

                key = [(key_int >> i) & 1 for i in range(9, -1, -1)]
                try:
                    encrypted = self._sdes.encrypt_block(plaintext, key)
                    if encrypted == target_ciphertext:
                        key_str = bit_list_to_string(key)
                        self.messageAppended.emit(f"找到密钥: {key_str}\n")
                        found_count += 1
                except Exception:
                    pass

                self.progressChanged.emit(key_int + 1)

            elapsed_time = time.time() - start_time
            self.messageAppended.emit(f"\n破解完成! 用时: {elapsed_time:.2f}秒\n")
            if found_count:
                self.messageAppended.emit(f"共找到 {found_count} 个可能的密钥\n")
            else:
                self.messageAppended.emit("未找到匹配的密钥\n")
        finally:
            self.finished.emit()

    def stop(self):
        self._running = False


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("S-DES 加解密系统 (PyQt)")
        self.resize(900, 720)
        self._sdes = SDES()

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        self.tabs = QtWidgets.QTabWidget()
        layout.addWidget(self.tabs)

        self._init_basic_tab()
        self._init_extend_tab()
        self._init_bruteforce_tab()
        self._init_analysis_tab()

        # 状态栏
        self.statusBar().showMessage("就绪")

        # 线程相关
        self._brute_thread = None
        self._brute_worker = None

    # 基本测试
    def _init_basic_tab(self):
        tab = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(tab)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("10位密钥 (二进制):"), 0, 0)
        self.key_input = QtWidgets.QLineEdit()
        self.key_input.setPlaceholderText("例如: 1010000010")
        form.addWidget(self.key_input, 0, 1)

        form.addWidget(QtWidgets.QLabel("8位明文 (二进制):"), 1, 0)
        self.plain_input = QtWidgets.QLineEdit()
        self.plain_input.setPlaceholderText("例如: 01110010")
        form.addWidget(self.plain_input, 1, 1)

        btn_encrypt = QtWidgets.QPushButton("加密")
        btn_encrypt.clicked.connect(self.encrypt_basic)
        form.addWidget(btn_encrypt, 2, 0)

        btn_decrypt = QtWidgets.QPushButton("解密")
        btn_decrypt.clicked.connect(self.decrypt_basic)
        form.addWidget(btn_decrypt, 2, 1)

        form.addWidget(QtWidgets.QLabel("结果:"), 3, 0)
        self.result_view = QtWidgets.QPlainTextEdit()
        self.result_view.setReadOnly(True)
        form.addWidget(self.result_view, 4, 0, 1, 2)

        btn_fill = QtWidgets.QPushButton("填充示例")
        btn_fill.clicked.connect(self.fill_example)
        form.addWidget(btn_fill, 5, 0, 1, 2)

        self.tabs.addTab(tab, "基本测试")

    # 扩展功能
    def _init_extend_tab(self):
        tab = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(tab)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("10位密钥 (二进制):"), 0, 0)
        self.ext_key_input = QtWidgets.QLineEdit()
        form.addWidget(self.ext_key_input, 0, 1)

        form.addWidget(QtWidgets.QLabel("文本:"), 1, 0)
        self.text_input = QtWidgets.QPlainTextEdit()
        form.addWidget(self.text_input, 2, 0, 1, 2)

        btn_encrypt = QtWidgets.QPushButton("加密文本")
        btn_encrypt.clicked.connect(self.encrypt_text)
        form.addWidget(btn_encrypt, 3, 0)

        btn_decrypt = QtWidgets.QPushButton("解密文本")
        btn_decrypt.clicked.connect(self.decrypt_text)
        form.addWidget(btn_decrypt, 3, 1)

        form.addWidget(QtWidgets.QLabel("结果:"), 4, 0)
        self.ext_result_view = QtWidgets.QPlainTextEdit()
        self.ext_result_view.setReadOnly(True)
        form.addWidget(self.ext_result_view, 5, 0, 1, 2)

        self.tabs.addTab(tab, "扩展功能")

    # 暴力破解
    def _init_bruteforce_tab(self):
        tab = QtWidgets.QWidget()
        form = QtWidgets.QGridLayout(tab)
        form.setContentsMargins(16, 16, 16, 16)
        form.setHorizontalSpacing(10)
        form.setVerticalSpacing(8)

        form.addWidget(QtWidgets.QLabel("已知明文 (二进制):"), 0, 0)
        self.known_plain_input = QtWidgets.QLineEdit()
        form.addWidget(self.known_plain_input, 0, 1)

        form.addWidget(QtWidgets.QLabel("已知密文 (二进制):"), 1, 0)
        self.known_cipher_input = QtWidgets.QLineEdit()
        form.addWidget(self.known_cipher_input, 1, 1)

        btn_start = QtWidgets.QPushButton("开始暴力破解")
        btn_start.clicked.connect(self.start_bruteforce)
        form.addWidget(btn_start, 2, 0)

        btn_stop = QtWidgets.QPushButton("停止破解")
        btn_stop.clicked.connect(self.stop_bruteforce)
        form.addWidget(btn_stop, 2, 1)

        form.addWidget(QtWidgets.QLabel("进度:"), 3, 0)
        self.progress_bar = QtWidgets.QProgressBar()
        self.progress_bar.setRange(0, 1024)
        form.addWidget(self.progress_bar, 3, 1)

        form.addWidget(QtWidgets.QLabel("破解结果:"), 4, 0)
        self.brute_result_view = QtWidgets.QPlainTextEdit()
        self.brute_result_view.setReadOnly(True)
        form.addWidget(self.brute_result_view, 5, 0, 1, 2)

        self.tabs.addTab(tab, "暴力破解")

    # 分析
    def _init_analysis_tab(self):
        tab = QtWidgets.QWidget()
        vbox = QtWidgets.QVBoxLayout(tab)
        vbox.setContentsMargins(16, 16, 16, 16)
        vbox.setSpacing(8)

        btn = QtWidgets.QPushButton("分析密钥冲突")
        btn.clicked.connect(self.analyze_key_conflicts)
        vbox.addWidget(btn)

        self.analysis_view = QtWidgets.QPlainTextEdit()
        self.analysis_view.setReadOnly(True)
        vbox.addWidget(self.analysis_view)

        self.tabs.addTab(tab, "封闭测试")

    # 业务槽函数
    def fill_example(self):
        self.key_input.setText("1010000010")
        self.plain_input.setText("01110010")

    def encrypt_basic(self):
        key_str = self.key_input.text().strip()
        plain_str = self.plain_input.text().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        if len(plain_str) != 8 or not all(bit in '01' for bit in plain_str):
            QtWidgets.QMessageBox.critical(self, "错误", "明文必须是8位二进制数")
            return
        key = string_to_bit_list(key_str)
        plaintext = string_to_bit_list(plain_str)
        ciphertext = self._sdes.encrypt_block(plaintext, key)
        ciphertext_str = bit_list_to_string(ciphertext)
        self.result_view.setPlainText(
            f"明文: {plain_str}\n密钥: {key_str}\n密文: {ciphertext_str}\n"
        )

    def decrypt_basic(self):
        key_str = self.key_input.text().strip()
        cipher_str = self.plain_input.text().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        if len(cipher_str) != 8 or not all(bit in '01' for bit in cipher_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密文必须是8位二进制数")
            return
        key = string_to_bit_list(key_str)
        ciphertext = string_to_bit_list(cipher_str)
        plaintext = self._sdes.decrypt_block(ciphertext, key)
        plaintext_str = bit_list_to_string(plaintext)
        self.result_view.setPlainText(
            f"密文: {cipher_str}\n密钥: {key_str}\n明文: {plaintext_str}\n"
        )

    def encrypt_text(self):
        key_str = self.ext_key_input.text().strip()
        text = self.text_input.toPlainText().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        key = string_to_bit_list(key_str)
        text_bits = self._sdes.string_to_bits(text)
        ciphertext_bits = self._sdes.encrypt(text_bits, key)
        ciphertext_hex = self._sdes.bits_to_hex(ciphertext_bits)
        ciphertext_str = self._sdes.bits_to_string(ciphertext_bits)
        self.ext_result_view.setPlainText(
            f"原文: {text}\n密钥: {key_str}\n密文(十六进制): {ciphertext_hex}\n密文(字符串): {ciphertext_str}\n"
        )

    def decrypt_text(self):
        key_str = self.ext_key_input.text().strip()
        text = self.text_input.toPlainText().strip()
        if len(key_str) != 10 or not all(bit in '01' for bit in key_str):
            QtWidgets.QMessageBox.critical(self, "错误", "密钥必须是10位二进制数")
            return
        key = string_to_bit_list(key_str)
        try:
            ciphertext_bits = self._sdes.hex_to_bits(text)
        except Exception:
            ciphertext_bits = self._sdes.string_to_bits(text)
        plaintext_bits = self._sdes.decrypt(ciphertext_bits, key)
        plaintext_str = self._sdes.bits_to_string(plaintext_bits)
        self.ext_result_view.setPlainText(
            f"密文: {text}\n密钥: {key_str}\n明文: {plaintext_str}\n"
        )

    def start_bruteforce(self):
        if self._brute_thread is not None:
            QtWidgets.QMessageBox.warning(self, "警告", "暴力破解正在进行中")
            return
        self.brute_result_view.clear()
        self.progress_bar.setValue(0)
        plaintext = self.known_plain_input.text().strip()
        ciphertext = self.known_cipher_input.text().strip()

        self._brute_thread = QtCore.QThread(self)
        self._brute_worker = BruteForceWorker(self._sdes, plaintext, ciphertext)
        self._brute_worker.moveToThread(self._brute_thread)
        self._brute_thread.started.connect(self._brute_worker.run)
        self._brute_worker.progressChanged.connect(self.progress_bar.setValue)
        self._brute_worker.messageAppended.connect(lambda s: self.brute_result_view.appendPlainText(s.strip("\n")))
        self._brute_worker.finished.connect(self._on_brute_finished)
        self._brute_thread.start()
        self.statusBar().showMessage("暴力破解中...")

    def stop_bruteforce(self):
        if self._brute_worker is not None:
            self._brute_worker.stop()

    def _on_brute_finished(self):
        try:
            if self._brute_thread is not None:
                self._brute_thread.quit()
                self._brute_thread.wait(2000)
        finally:
            self._brute_thread = None
            self._brute_worker = None
            self.statusBar().showMessage("就绪")

    def analyze_key_conflicts(self):
        import random
        self.analysis_view.clear()
        self.analysis_view.appendPlainText("开始分析密钥冲突...")
        test_plaintext = [random.randint(0, 1) for _ in range(8)]
        plaintext_str = bit_list_to_string(test_plaintext)
        ciphertext_to_keys = {}
        key_conflicts = []
        start_time = time.time()
        for key_int in range(1024):
            key = [(key_int >> i) & 1 for i in range(9, -1, -1)]
            key_str = bit_list_to_string(key)
            try:
                ciphertext = self._sdes.encrypt_block(test_plaintext, key)
                ciphertext_str = bit_list_to_string(ciphertext)
                if ciphertext_str in ciphertext_to_keys:
                    existing_key = ciphertext_to_keys[ciphertext_str]
                    key_conflicts.append((existing_key, key_str, ciphertext_str))
                else:
                    ciphertext_to_keys[ciphertext_str] = key_str
            except Exception:
                pass
        elapsed_time = time.time() - start_time
        self.analysis_view.appendPlainText(f"\n分析完成! 用时: {elapsed_time:.2f}秒")
        self.analysis_view.appendPlainText(f"测试明文: {plaintext_str}")
        self.analysis_view.appendPlainText(f"不同密文数量: {len(ciphertext_to_keys)}")
        self.analysis_view.appendPlainText(f"密钥冲突数量: {len(key_conflicts)}\n")
        if key_conflicts:
            self.analysis_view.appendPlainText("发现的密钥冲突:")
            for i, (key1, key2, ciphertext) in enumerate(key_conflicts[:10]):
                self.analysis_view.appendPlainText(
                    f"冲突 {i + 1}: 密钥 {key1} 和 {key2} 产生相同密文 {ciphertext}"
                )
            if len(key_conflicts) > 10:
                self.analysis_view.appendPlainText(
                    f"... 还有 {len(key_conflicts) - 10} 个冲突未显示"
                )
        else:
            self.analysis_view.appendPlainText("未发现密钥冲突")


def load_qss(app: QtWidgets.QApplication, qss_path: str = "styles.qss") -> None:
    try:
        with open(qss_path, "r", encoding="utf-8") as f:
            app.setStyleSheet(f.read())
    except Exception:
        pass


def main():
    # 高DPI/缩放
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling, True)
    QtWidgets.QApplication.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps, True)

    app = QtWidgets.QApplication(sys.argv)

    # 现代默认字体
    font = QtGui.QFont("Microsoft YaHei UI", 10)
    app.setFont(font)

    # 可选：统一平台风格
    app.setStyle("Fusion")

    # 加载样式
    load_qss(app)

    w = MainWindow()
    w.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()



