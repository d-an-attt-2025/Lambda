\# Lambda Clear Blacklist – IPSet Cleanup Automation



\## Mục đích

Lambda này tự động xóa các IP đã bị block trong AWS WAF IPSet theo chu kỳ định sẵn.



\## Lý do triển khai

\- Tránh block vĩnh viễn IP hợp lệ

\- Giảm rủi ro false positive

\- Đảm bảo blacklist luôn phản ánh trạng thái tấn công hiện tại



\## Luồng hoạt động

1\. EventBridge (cron schedule) kích hoạt Lambda

2\. Lambda:

&nbsp;  - Lấy danh sách IP trong WAF IPSet

&nbsp;  - Xóa toàn bộ hoặc từng IP theo chính sách



\## Lịch chạy

\- Định kỳ theo cron (ví dụ: hàng ngày / 2h sáng)

\- Có thể invoke thủ công để kiểm tra



\## Công nghệ sử dụng

\- AWS Lambda

\- Amazon EventBridge

\- AWS WAFv2



\## Đầu vào

\- Sự kiện EventBridge theo lịch



\## Đầu ra

\- IPSet được làm sạch

\- Log audit trên CloudWatch Logs



