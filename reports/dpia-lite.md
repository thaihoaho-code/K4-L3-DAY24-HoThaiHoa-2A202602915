# DPIA-lite (bài tập mô tả luồng)

Tài liệu học tập này không phải hồ sơ đánh giá tác động pháp lý chính thức, tư vấn pháp lý hay kết luận tuân thủ.

## 1. Dữ liệu nào?

Run A tìm các ticket trong corpus giả lập. Ticket có thể chứa thông tin liên hệ hoặc định danh; nội dung được đưa qua bộ regex PII và che trước khi chuyển cho bước tóm tắt. Run B có thể đọc hồ sơ khách hàng giả trong `data/customers.json`, gồm mã khách, thông tin cá nhân mẫu và các ticket liên quan. Ledger lưu hash tham số thay vì ghi nguyên hồ sơ/PII.

## 2. Ai và mục đích nào?

`support_l1` được mô phỏng với quyền tìm ticket; không được mở hồ sơ riêng. `dpo` được mô phỏng với quyền đọc hồ sơ cho mục đích `support-reply`, nếu policy, scope và thời hạn đều hợp lệ. Tham số `--as dpo` chỉ chọn dòng quyền giả lập trong file; nó không xác minh danh tính người đang chạy chương trình.

## 3. Dữ liệu đi qua đâu?

Run A gọi `search_docs`, lấy số ticket từ tên file, che PII trong nội dung rồi tạo tóm tắt. Run B nhận danh sách số ticket, policy-gate trước khi đọc danh sách liên quan và kiểm lại ngay trước từng `read_customer`. Nếu văn bản gợi ý gửi ra ngoài, runner thực hiện kiểm policy riêng cho `http_post` với URL; kiểm tra restricted+egress bị deny trước khi gọi tool. Ledger ghi kết quả, lý do và hash tham số. Tool sink chỉ cho phép localhost; đây là rào chắn lab bổ sung, không phải policy containment.

## 4. Đã chặn/cho phép gì và còn giới hạn gì?

Đã cho phép đọc ticket theo quyền; DPO có thể đọc khách có ticket thực sự liên quan. Đã chặn `support_l1` khỏi private store và chặn egress khi dữ liệu restricted; lượt kiểm gửi bị ghi deny với lý do và `on_behalf_of`. So sánh hiện tại cho thấy `reports/attack-before.log` có POST chứa khách giả `KH-000999`, `reports/attack-after.log` rỗng và ledger xác minh hash chain thành công.

Giới hạn: corpus, khách hàng và principal là giả; chọn `dpo` không phải đăng nhập/xác thực. LLM/mock và regex không đảm bảo phát hiện mọi lure hoặc PII; regex có thể bỏ sót và nhận nhầm. Hash chain phát hiện sửa nội dung giữa chuỗi nếu không tính lại hash, nhưng không tự ngăn xóa đuôi chuỗi hay kẻ có quyền tính lại toàn chuỗi. Sink localhost chỉ phục vụ bài tập, không đại diện cho dịch vụ thật.
