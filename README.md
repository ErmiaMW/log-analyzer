# Access Log Analyzer

<div dir="rtl" align="right">

ابزاری مبتنی بر خط فرمان برای تحلیل فایل‌های <span dir="ltr">Access Log</span> وب‌سرور است.

این برنامه فایل‌های Log را پردازش می‌کند، خطوط خراب را بدون متوقف شدن برنامه کنار می‌گذارد، شاخص‌های ترافیک و خطا را محاسبه می‌کند، فعالیت‌های مشکوک در مسیر <code dir="ltr">/login</code> را تشخیص می‌دهد، جهش‌های غیرعادی خطاهای <code dir="ltr">5xx</code> را پیدا می‌کند و گزارشی خوانا در Terminal نمایش می‌دهد.

این ابزار از فایل‌های متنی معمولی و فایل‌های فشرده‌شده با فرمت <code dir="ltr">.gz</code> پشتیبانی می‌کند.

</div>

<h2 dir="rtl" align="right">قابلیت‌ها</h2>

<ul dir="rtl">
  <li>پردازش Streaming فایل‌های Log</li>
  <li>پشتیبانی از <span dir="ltr">Combined Log Format</span></li>
  <li>مدیریت امن خطوط malformed</li>
  <li>شمارش کل Requestها</li>
  <li>شمارش IPهای یکتا</li>
  <li>نمایش پرتکرارترین Endpointها</li>
  <li>نمایش پرتکرارترین IPها</li>
  <li>شمارش پاسخ‌های <code dir="ltr">4xx</code> و <code dir="ltr">5xx</code></li>
  <li>محاسبه <span dir="ltr">Error Rate</span></li>
  <li>نمایش Histogram ترافیک ساعتی</li>
  <li>تشخیص ساعت اوج و ساعت کمینه ترافیک</li>
  <li>امکان تعیین تعداد نتایج برتر با <code dir="ltr">--top</code></li>
  <li>فیلتر کردن Requestها بر اساس بازه زمانی</li>
  <li>پشتیبانی از فایل‌های معمولی و فایل‌های <code dir="ltr">.gz</code></li>
  <li>تولید گزارش JSON</li>
  <li>تشخیص تلاش‌های ناموفق مشکوک روی <code dir="ltr">/login</code></li>
  <li>تشخیص خودکار جهش نرخ خطاهای <code dir="ltr">5xx</code></li>
  <li>نمایش زمان اجرای تحلیل</li>
  <li>پیاده‌سازی فقط با <span dir="ltr">Python Standard Library</span></li>
</ul>

<h2 dir="rtl" align="right">ساختار پروژه</h2>

```text
log-analyzer/
├── log_analyzer/
│   ├── __init__.py
│   ├── __main__.py
│   ├── analyzer.py
│   ├── cli.py
│   ├── detector.py
│   ├── models.py
│   ├── parser.py
│   ├── reader.py
│   └── reporter.py
│
├── tests/
│   ├── fixtures/
│   │   ├── sample1.log
│   │   ├── sample2.log
│   │   └── sample2.log.gz
│   ├── __init__.py
│   ├── test_analyzer.py
│   └── test_parser.py
│
├── .gitignore
└── README.md
```

<h2 dir="rtl" align="right">گزینه‌های خط فرمان</h2>

```text
usage: log-analyzer [-h] [--top N] [--from DATETIME] [--to DATETIME]
                    [--json] [--login-threshold N] log_file
```

<div dir="rtl" align="right">

<table>
  <thead>
    <tr>
      <th align="right">گزینه</th>
      <th align="right">توضیح</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td><code dir="ltr">log_file</code></td>
      <td>مسیر فایل  Log معمولی یا فشرده‌شده با فرمت <code dir="ltr">.gz</code></td>
    </tr>
    <tr>
      <td><code dir="ltr">--top N</code></td>
      <td>تعداد Endpointها و IPهای برتر برای نمایش</td>
    </tr>
    <tr>
      <td><code dir="ltr">--from DATETIME</code></td>
      <td>زمان شروع بازه تحلیل</td>
    </tr>
    <tr>
      <td><code dir="ltr">--to DATETIME</code></td>
      <td>زمان پایان بازه تحلیل</td>
    </tr>
    <tr>
      <td><code dir="ltr">--json</code></td>
      <td>ذخیره گزارش ساختاریافته در فایل <code dir="ltr">report.json</code></td>
    </tr>
    <tr>
      <td><code dir="ltr">--login-threshold N</code></td>
      <td>حداقل تعداد پاسخ‌های <code dir="ltr">401</code> روی مسیر <code dir="ltr">/login</code> برای مشکوک در نظر گرفتن یک IP</td>
    </tr>
    <tr>
      <td><code dir="ltr">-h</code>، <code dir="ltr">--help</code></td>
      <td>نمایش راهنمای برنامه</td>
    </tr>
  </tbody>
</table>

مقدار پیش‌فرض <code dir="ltr">--top</code> برابر با <code dir="ltr">10</code> است.

مقدار پیش‌فرض <code dir="ltr">--login-threshold</code> برابر با <code dir="ltr">20</code> است.

مقادیر زمانی باید با فرمت <span dir="ltr">ISO 8601</span> و همراه با Timezone وارد شوند.

</div>

<h2 dir="rtl" align="right">مثال‌های اجرا</h2>

<div dir="rtl" align="right">

تحلیل یک فایل Log:

</div>

```bash
python -m log_analyzer access.log
```

<div dir="rtl" align="right">

نمایش پنج Endpoint و IP برتر:

</div>

```bash
python -m log_analyzer access.log --top 5
```

<div dir="rtl" align="right">

تحلیل Requestهای یک بازه زمانی مشخص:

</div>

```bash
python -m log_analyzer access.log \
  --from 2026-06-01T09:00:00+00:00 \
  --to 2026-06-01T10:00:00+00:00
```


<div dir="rtl" align="right">

تولید گزارش JSON:

</div>

```bash
python -m log_analyzer access.log --json
```

<div dir="rtl" align="right">

در این حالت، گزارش متنی همچنان در Terminal نمایش داده می‌شود و گزارش ساختاریافته نیز در فایل زیر ذخیره می‌شود:

</div>

```text
report.json
```

<div dir="rtl" align="right">

تحلیل یک فایل فشرده‌شده:

</div>

```bash
python -m log_analyzer access.log.gz
```

<div dir="rtl" align="right">

تغییر Threshold تشخیص فعالیت مشکوک:

</div>

```bash
python -m log_analyzer access.log \
  --login-threshold 50
```

<h2 dir="rtl" align="right">نمونه خروجی</h2>

<div dir="rtl" align="right">

خروجی زیر با استفاده از  فایل Access Log شامل <code dir="ltr">500,000</code> خط تولید شده است:

</div>

```text
Log Analysis Report
===================
Execution Time:               7.390 s

Summary
-------
Total Lines:                  500,000
Total Requests:               495,044
Filtered Requests:                  0
Malformed Lines:                4,956
Unique IPs:                     4,001
4xx Responses:                 26,637
5xx Responses:                 24,438
Error Rate:                    10.32%

Top 5 Endpoints
---------------
 1. /                                      146,302
 2. /products                               87,685
 3. /api/search                             48,842
 4. /cart                                   34,181
 5. /login                                  31,658

Top 5 IPs
---------
 1. 21.67.75.144                             7,464
 2. 169.214.192.18                             160
 3. 88.33.11.24                                160
 4. 44.64.147.243                              158
 5. 208.64.231.113                             157

Peak Hour: 2026-06-01 00:00 +0000 (51,026 requests)
Quiet Hour: 2026-06-01 09:00 +0000 (36,953 requests)

Security Findings
-----------------
Suspicious Login Activity
- 21.67.75.144: 7,464 failed /login attempts (401)

5xx Error Spikes
- 2026-06-01 04:00 +0000: 3,640/50,847 requests (7.16%)
- 2026-06-01 05:00 +0000: 8,983/51,002 requests (17.61%)
```

<div dir="rtl" align="right">

بخش ترافیک ساعتی به شکل یک Histogram در Terminal نمایش داده می‌شود:

</div>

```text
Hourly Traffic
--------------
00 ████████████████████████████████████████  51,026
01 ████████████████████████████████████████  50,971
02 ████████████████████████████████████████  50,975
03 ████████████████████████████████████████  50,705
04 ████████████████████████████████████████  50,847
05 ████████████████████████████████████████  51,002
06 ████████████████████████████████████████  50,809
07 ████████████████████████████████████████  50,844
08 ████████████████████████████████████████  50,912
09 █████████████████████████████             36,953
```

<h2 dir="rtl" align="right">معماری</h2>

<div dir="rtl" align="right">


<h3><code dir="ltr">reader.py</code></h3>

فایل‌های متنی معمولی و فایل‌های فشرده‌شده با فرمت <code dir="ltr">.gz</code> را به‌صورت Text Stream باز می‌کند.

<h3><code dir="ltr">parser.py</code></h3>

هر خط Log را Parse می‌کند و در صورت معتبر بودن، یک شیء از نوع <code dir="ltr">LogEntry</code> برمی‌گرداند.

اگر ساختار خط نامعتبر باشد، مقدار <code dir="ltr">None</code> برگردانده می‌شود و پردازش سایر خطوط ادامه پیدا می‌کند.

<h3><code dir="ltr">models.py</code></h3>

Data Modelهای مربوط به Logهای Parseشده و نتایج نهایی تحلیل را نگهداری می‌کند.

<h3><code dir="ltr">analyzer.py</code></h3>

Requestهای معتبر را پردازش می‌کند و Metricهای موردنیاز را به‌روزرسانی می‌کند.

موارد زیر در این بخش محاسبه می‌شوند:

<ul>
  <li>تعداد کل Requestها</li>
  <li>تعداد خطوط malformed</li>
  <li>تعداد Requestهای حذف‌شده توسط Time Filter</li>
  <li>تعداد IPهای یکتا</li>
  <li>تعداد Requestهای هر Endpoint</li>
  <li>تعداد Requestهای هر IP</li>
  <li>ترافیک ساعتی</li>
  <li>تعداد پاسخ‌های <code dir="ltr">4xx</code></li>
  <li>تعداد پاسخ‌های <code dir="ltr">5xx</code></li>
  <li>تعداد پاسخ‌های <code dir="ltr">401</code> روی <code dir="ltr">/login</code></li>
  <li>تعداد خطاهای <code dir="ltr">5xx</code> در هر ساعت</li>
</ul>

<h3><code dir="ltr">detector.py</code></h3>

Ruleهای مربوط به تشخیص فعالیت مشکوک و جهش نرخ خطاهای <code dir="ltr">5xx</code> را اجرا می‌کند.

<h3><code dir="ltr">reporter.py</code></h3>

گزارش متنی مناسب Terminal و گزارش ساختاریافته JSON را تولید می‌کند.

<h3><code dir="ltr">cli.py</code></h3>

Argumentهای خط فرمان را دریافت می‌کند و اجرای بخش‌های مختلف برنامه را هماهنگ می‌کند.

</div>

```text
CLI
 |
 v
Reader
 |
 v
Parser
 |
 v
Analyzer
 |
 v
Detector
 |
 v
Reporter
```

<h2 dir="rtl" align="right">تصمیم‌های طراحی</h2>

<h3 dir="rtl" align="right">استفاده از <code dir="ltr">Counter</code></h3>

<div dir="rtl" align="right">

برای شمارش Endpointها، IPها، ترافیک ساعتی و خطاها از <code dir="ltr">Counter</code> استفاده شده است.

این ساختار امکان به‌روزرسانی مستقیم تعداد رخدادها را فراهم می‌کند و منطق Aggregation را ساده نگه می‌دارد.

</div>

<h3 dir="rtl" align="right">استفاده از <code dir="ltr">set</code> برای IPهای یکتا</h3>

<div dir="rtl" align="right">

برای نگهداری IPهای یکتا از <code dir="ltr">set</code> استفاده شده است.

مقادیر تکراری به‌صورت خودکار حذف می‌شوند و در پایان، تعداد IPهای یکتا با استفاده از طول مجموعه محاسبه می‌شود.

</div>

<h3 dir="rtl" align="right">حذف Query String از Endpointها</h3>

<div dir="rtl" align="right">

قبل از شمارش ترافیک Endpointها، Query Parameterها حذف می‌شوند.

برای مثال:

</div>

```text
/products?page=1
/products?page=2
/products?sort=price
```

<div dir="rtl" align="right">

همگی به شکل زیر نرمال‌سازی می‌شوند:

</div>

```text
/products
```

<div dir="rtl" align="right">

این کار مانع از آن می‌شود که Pagination، Filtering یا Sorting باعث ایجاد چند Endpoint جداگانه برای یک Resource شوند.

بخش‌های مختلف Path به‌صورت خودکار نرمال‌سازی نمی‌شوند.

برای مثال:

</div>

```text
/products/123
/products/456
```

<div dir="rtl" align="right">

این دو مسیر به‌عنوان دو Endpoint جداگانه باقی می‌مانند؛ زیرا برنامه به Route Definitionهای سیستم دسترسی ندارد و نباید فرض کند که هر دو مسیر از الگوی زیر استفاده می‌کنند:

</div>

```text
/products/{id}
```

<h2 dir="rtl" align="right">تشخیص فعالیت‌های غیرعادی</h2>

<h3 dir="rtl" align="right">فعالیت مشکوک روی <code dir="ltr">/login</code></h3>

<div dir="rtl" align="right">

برنامه Requestهایی را شمارش می‌کند که هر دو شرط زیر را داشته باشند:

</div>

```text
endpoint = /login
status = 401
```

<div dir="rtl" align="right">

زمانی که تعداد تلاش‌های ناموفق یک IP به Threshold تعیین‌شده برسد، آن IP به‌عنوان مورد مشکوک گزارش می‌شود.

Threshold پیش‌فرض:

</div>

```text
20 attempts
```

<div dir="rtl" align="right">

این مقدار از طریق CLI قابل تغییر است:

</div>

```bash
python -m log_analyzer access.log \
  --login-threshold 50
```

<h3 dir="rtl" align="right">تشخیص جهش خطاهای <code dir="ltr">5xx</code></h3>

<div dir="rtl" align="right">

برنامه نرخ خطاهای <code dir="ltr">5xx</code> را برای هر بازه ساعتی محاسبه می‌کند.

از Median نرخ خطای ساعتی به‌عنوان Baseline استفاده شده است؛ زیرا Median نسبت به مقادیر بسیار بزرگ و Spikeهای غیرعادی حساسیت کمتری دارد.

یک ساعت زمانی به‌عنوان Spike گزارش می‌شود که تمام شرایط زیر برقرار باشند:

<ul>
  <li>حداقل <code dir="ltr">100</code> Request در آن ساعت ثبت شده باشد</li>
  <li>حداقل <code dir="ltr">10</code> پاسخ از نوع <code dir="ltr">5xx</code> وجود داشته باشد</li>
  <li>نرخ خطای <code dir="ltr">5xx</code> حداقل <code dir="ltr">5%</code> باشد</li>
  <li>نرخ خطای <code dir="ltr">5xx</code> حداقل دو برابر Median Baseline باشد</li>
</ul>

این محدودیت‌ها احتمال ایجاد False Positive در ساعت‌هایی با ترافیک بسیار کم را کاهش می‌دهند.

</div>

<h2 dir="rtl" align="right">تست‌ها</h2>

<div dir="rtl" align="right">

تست‌ها با استفاده از Framework داخلی <code dir="ltr">unittest</code> نوشته شده‌اند.

برای اجرای تمام تست‌ها:

</div>

```bash
python -m unittest discover -v
```

<div dir="rtl" align="right">

موارد زیر در تست‌ها بررسی می‌شوند:

<ul>
  <li>Parse صحیح خطوط معتبر</li>
  <li>رد کردن خطوط malformed</li>
  <li>حذف Query Parameterها</li>
  <li>شمارش Requestها</li>
  <li>شمارش خطوط malformed</li>
  <li>شمارش IPهای یکتا</li>
  <li>شمارش Requestهای هر Endpoint</li>
  <li>شمارش پاسخ‌های <code dir="ltr">4xx</code> و <code dir="ltr">5xx</code></li>
  <li>محاسبه Error Rate</li>
  <li>محاسبه ترافیک ساعتی</li>
  <li>مدیریت ورودی خالی</li>
  <li>اعمال Time Filter</li>
</ul>

نمونه نتیجه اجرای تست‌ها:

</div>

```text
test_aggregates_log_statistics ... ok
test_applies_time_range_filter ... ok
test_handles_empty_input ... ok
test_parses_valid_log_line ... ok
test_removes_query_parameters ... ok
test_returns_none_for_malformed_line ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.003s

OK
```

<div dir="rtl" align="right">

فایل‌های نمونه تست در مسیر زیر قرار دارند:

</div>

```text
tests/fixtures/
```

<div dir="rtl" align="right">

این فایل‌ها شامل Requestهای معتبر، خطوط malformed، Query Parameter، خطاهای Authentication، پاسخ‌های <code dir="ltr">5xx</code> و نمونه فشرده‌شده با فرمت <code dir="ltr">.gz</code> هستند.

</div>

<h2 dir="rtl" align="right">چالش‌ها و راه‌حل‌ها</h2>

<h3 dir="rtl" align="right">شمارش معنادار Endpointها</h3>

<div dir="rtl" align="right">

شمارش مستقیم Request Target باعث می‌شود هر Query String به‌عنوان یک Endpoint جداگانه در نظر گرفته شود.

برای مثال:

</div>

```text
/products?page=1
/products?page=2
```

<div dir="rtl" align="right">

بدون نرمال‌سازی، این دو مسیر به‌عنوان دو Endpoint متفاوت شمارش می‌شوند.

برای حل این مشکل، Query String قبل از Aggregation حذف می‌شود تا Requestهای مربوط به یک Resource در یک گروه قرار بگیرند.

Dynamic Pathها به‌صورت خودکار تغییر داده نمی‌شوند؛ زیرا Route Definitionهای برنامه در دسترس نیستند.

</div>

<h3 dir="rtl" align="right">مدیریت ورودی‌های خراب</h3>

<div dir="rtl" align="right">

فایل‌های  Log ممکن است شامل خطوط ناقص، Timestamp نامعتبر یا داده‌هایی با ساختار اشتباه باشند.

Parser ساختار کامل هر خط را بررسی می‌کند و در صورت نامعتبر بودن، مقدار <code dir="ltr">None</code> برمی‌گرداند.

Analyzer تعداد خطوط malformed را ثبت می‌کند و پردازش سایر خطوط را ادامه می‌دهد.

در نتیجه، وجود یک خط خراب باعث متوقف شدن تحلیل یک فایل بزرگ نمی‌شود.

</div>