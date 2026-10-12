# Secret giả trong lịch sử Git

- **Scanner/version:** Gitleaks v8.30.1, theo hook `gitleaks-system` đã pin tại `rev: v8.30.1` trong `.pre-commit-config.yaml`.
- **Finding lịch sử:** commit `1bdd849` (`chore: seed student lab with synthetic secret exercise`), file `lab-fake-secret.txt`, rule `lab24-synthetic-token`. Lệnh `gitleaks git --config .gitleaks.toml` quét 4 commit (~138.24 KB) trong 397 ms và báo 1 finding. Đây là token giả, vô hiệu, dành cho bài lab; không ghi giá trị token vào báo cáo.
- **File hiện tại:** `gitleaks dir --config .gitleaks.toml --redact .` quét ~37.32 MB trong 8.41 giây, không tìm thấy leak. `pre-commit run --all-files` cũng Passed; `tests/test_supply_chain.py` có 3/3 test Passed.
- **Nếu là secret thật:** thu hồi/rotate tại dịch vụ đã cấp token; kiểm tra log và hoạt động để tìm việc sử dụng trái phép; sau đó xử lý các bản sao trong repo, lịch sử Git, clone, cache và nơi lưu trữ liên quan. Xóa file ở commit mới không làm token cũ tự vô hiệu.
- **Giới hạn:** pin dependency và hook giúp phát hiện hoặc giảm rủi ro secret mới bị commit, nhưng không thu hồi token đã lộ và không tự xóa các bản sao trong lịch sử hay clone.
