use super::util::now;
use super::*;

use uuid::Uuid;

pub(super) fn draft_outreach_note(venture: &Venture, customer: &Customer, zh: bool) -> String {
    // Deterministic local drafting logic — this is the "assistant" content.
    // It composes from known facts only; it invents nothing and cites no
    // numbers, so an unreviewed copy is safe.
    if zh {
        format!(
            "你好 {customer},\n\n我是 {venture} 的负责人。{service}——如果这正是你们现在需要的,我很乐意约个简短的通话,聊聊你们的目标和时间安排。\n\n期待回音。\n\n(本地起草助手草拟 · 未保存 · 请审阅后再使用)",
            customer = customer.name,
            venture = venture.name,
            service = venture.service,
        )
    } else {
        format!(
            "Hi {customer},\n\nI'm the founder of {venture}. {service} — if that's useful to you right now, I'd be glad to set up a short call to understand your goals and timeline.\n\nLooking forward to hearing from you.\n\n(drafted by the local assistant · not saved · review before use)",
            customer = customer.name,
            venture = venture.name,
            service = venture.service,
        )
    }
}

pub(super) fn render_document(
    kind: DocumentKind,
    venture: &Venture,
    customer: &Customer,
    amount_cents: Option<u64>,
    zh: bool,
) -> Document {
    // Deterministic templates by design: no model output enters authoritative
    // business state in this stage.
    let (title, body) = match (kind, zh) {
        (DocumentKind::Offer, false) => (
            format!("Offer — {} for {}", venture.name, customer.name),
            format!(
                "OFFER (DRAFT)\n\nFrom: {}\nTo: {}\n\nProposed service:\n{}\n\nScope, timeline, and pricing to be confirmed together.\nThis draft was generated locally by Sovereign Founder OS; no model was involved and nothing has been sent.",
                venture.name, customer.name, venture.service
            ),
        ),
        (DocumentKind::Offer, true) => (
            format!("报价单 — {} 致 {}", venture.name, customer.name),
            format!(
                "报价单(草稿)\n\n发件方:{}\n客户:{}\n\n拟提供的服务:\n{}\n\n范围、周期与价格待双方确认。\n本草稿由 Sovereign Founder OS 在本地生成;未使用任何模型,也未发送给任何人。",
                venture.name, customer.name, venture.service
            ),
        ),
        (DocumentKind::Invoice, false) => (
            format!("Invoice — {} to {}", venture.name, customer.name),
            format!(
                "INVOICE (DRAFT)\n\nFrom: {}\nBill to: {}\nAmount: {}\n\nPayment terms to be confirmed.\nThis draft was generated locally by Sovereign Founder OS and has not been issued.",
                venture.name,
                customer.name,
                format_amount(amount_cents.unwrap_or(0)),
            ),
        ),
        (DocumentKind::Invoice, true) => (
            format!("发票草稿 — {} 致 {}", venture.name, customer.name),
            format!(
                "发票(草稿)\n\n开票方:{}\n客户:{}\n金额:{}\n\n付款条款待确认。\n本草稿由 Sovereign Founder OS 在本地生成,尚未开具。",
                venture.name,
                customer.name,
                format_amount(amount_cents.unwrap_or(0)),
            ),
        ),
    };
    Document {
        id: Uuid::new_v4(),
        kind,
        customer_id: customer.id,
        title,
        body,
        amount_cents,
        status: DocumentStatus::Draft,
        created_at: now(),
    }
}

fn format_amount(cents: u64) -> String {
    format!("$ {}.{:02}", cents / 100, cents % 100)
}

/// Compose a well-formed RFC 5322 message for an approved document. The result
/// is written to the local outbox and never transmitted — an `X-Sovereign`
/// header says so, and a missing recipient becomes an RFC 2606 `.invalid`
/// placeholder the founder must replace before sending. Header values come from
/// validated fields (names carry no control characters, emails no CR/LF or
/// separators), and are re-sanitized here, so no field can inject a header.
pub(super) fn compose_email(
    venture: Option<&Venture>,
    customer: Option<&Customer>,
    document: &Document,
) -> String {
    let sender_name = venture
        .map(|venture| venture.name.as_str())
        .unwrap_or("Sovereign Founder");
    let recipient_name = customer
        .map(|customer| customer.name.as_str())
        .unwrap_or("Customer");
    let recipient_addr = customer
        .map(|customer| customer.email.trim())
        .filter(|email| !email.is_empty())
        .map(|email| email.to_owned())
        .unwrap_or_else(|| "recipient@example.invalid".to_owned());
    let placeholder = recipient_addr.ends_with(".invalid");

    let mut message = String::new();
    message.push_str(&format!(
        "From: {} <founder@example.invalid>\r\n",
        encode_display_name(sender_name)
    ));
    message.push_str(&format!(
        "To: {} <{}>\r\n",
        encode_display_name(recipient_name),
        header_safe(&recipient_addr)
    ));
    message.push_str(&format!("Subject: {}\r\n", header_safe(&document.title)));
    message.push_str(&format!("Date: {}\r\n", chrono::Utc::now().to_rfc2822()));
    message.push_str(&format!(
        "Message-ID: <{}@sovereign-founder-os.invalid>\r\n",
        document.id.simple()
    ));
    message.push_str("MIME-Version: 1.0\r\n");
    message.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    message.push_str(
        "X-Sovereign-Composed: composed locally by Sovereign Founder OS; not transmitted\r\n",
    );
    if placeholder {
        message.push_str(
            "X-Sovereign-Note: recipient address is a placeholder — set the customer's email before sending\r\n",
        );
    }
    message.push_str("\r\n");
    for line in document.body.split('\n') {
        message.push_str(line.trim_end_matches('\r'));
        message.push_str("\r\n");
    }
    message
}

/// Render an RFC 5322 display-name: kept bare when it is a safe atom, otherwise
/// a quoted-string with `\\` and `"` escaped. CR/LF are stripped defensively.
fn encode_display_name(name: &str) -> String {
    let sanitized: String = name
        .chars()
        .filter(|ch| *ch != '\r' && *ch != '\n')
        .collect();
    let needs_quoting = sanitized.is_empty()
        || sanitized
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || " !#$%&'*+-/=?^_`{|}~".contains(ch)));
    if needs_quoting {
        let escaped = sanitized.replace('\\', "\\\\").replace('"', "\\\"");
        format!("\"{escaped}\"")
    } else {
        sanitized
    }
}

/// Collapse any CR/LF in a single-line header value to spaces — defense in
/// depth against header injection on top of upstream field validation.
fn header_safe(value: &str) -> String {
    value.replace(['\r', '\n'], " ")
}
