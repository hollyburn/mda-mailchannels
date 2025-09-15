use std::collections::HashMap;
use std::default::Default;
use std::io::Read;

use mail_parser::{HeaderName, HeaderValue, MimeHeaders};

use quick_error::quick_error;

use serde_with::base64::Base64;
use serde_with::{serde_as, skip_serializing_none};

const fn api_key() -> &'static str {
    env!("MDA_MAILCHANNELS_API_KEY")
}

const fn dkim_selector() -> &'static str {
    env!("MDA_MAILCHANNELS_DKIM_SELECTOR")
}

mod headers {
    use mail_parser::HeaderName;
    /* headers we can't use, per MailChannels API docs:
     * Authentication-Results (assuming this means Arc-Authentication-Results)
     * BCC CC
     * Content-Transfer-Encoding Content-Type
     * DKIM-Signature
     * From Message-ID Received Reply-To Subject To
     */
    pub(crate) const FORBIDDEN: &[HeaderName] = &[
        HeaderName::ArcAuthenticationResults, // stripped
        HeaderName::Bcc,                      // converted to Personalization
        HeaderName::Cc,                       // converted to Personalization
        HeaderName::ContentTransferEncoding,  // converted to Content
        HeaderName::ContentType,              // converted to Content
        HeaderName::DkimSignature,            // stripped. email is signed after submission to api
        HeaderName::From,                     // included in json body
        HeaderName::MessageId,                // stripped
        HeaderName::Received,                 // stripped
        HeaderName::ReplyTo,                  // included in json body
        HeaderName::Subject,                  // included in json body
        HeaderName::To,                       // converted to Personali
    ];
}

#[skip_serializing_none]
#[derive(serde::Serialize)]
struct MailChannelsBody {
    attachments: Option<Vec<Attachment>>,
    content: Vec<Content>,
    #[serde(flatten)]
    dkim: DkimInfo,
    from: Address,
    headers: Option<HashMap<String, String>>,
    personalizations: Vec<Personalization>,
    reply_to: Option<Address>,
    subject: String,
    tracking_settings: Option<TrackingSettings>,
    #[serialize_always]
    transactional: Option<bool>,
}

#[serde_as]
#[derive(serde::Serialize)]
struct Attachment {
    #[serde_as(as = "Base64")]
    content: Vec<u8>,
    filename: String,
    #[serde(rename = "type")]
    mimetype: String,
}

#[derive(serde::Serialize)]
struct Content {
    template_type: Option<String>,
    #[serde(rename = "type")]
    content_type: String,
    value: String,
}

#[serde_as]
#[derive(serde::Serialize)]
struct DkimInfo {
    dkim_domain: String,
    dkim_private_key: String,
    dkim_selector: String,
}

#[derive(serde::Serialize)]
struct Personalization {
    bcc: Option<Vec<Address>>,
    cc: Option<Vec<Address>>,
    #[serde(flatten)]
    dkim: Option<DkimInfo>,
    dynamic_template_data: Option<HashMap<String, ()>>, //TemplateValue>>,
    from: Option<Address>,
    headers: Option<HashMap<String, String>>,
    reply_to: Option<Address>,
    subject: Option<String>,
    to: Vec<Address>,
}

// #[derive(serde::Serialize)]
// enum TemplateValue {
//     String(String),
//     Boolean(bool),
//     Number(f64),
//     List(Vec<TemplateValue>),
//     Map(HashMap<String, TemplateValue>),
// }

#[derive(serde::Serialize)]
struct TrackingSettings {
    click_tracking: Option<ShouldEnable>,
    open_tracking: Option<ShouldEnable>,
}

#[derive(serde::Serialize)]
struct ShouldEnable {
    enable: bool,
}

#[derive(serde::Serialize, Clone)]
struct Address {
    name: Option<String>,
    email: String,
}

quick_error! {
    #[derive(Debug)]
    enum MainError {
        Reqwest(err: reqwest::Error) { from() }
        HeaderValue(err: reqwest::header::InvalidHeaderValue) { from() }
        Io(err: std::io::Error) { from() }
        NoHeaders(err: &'static str)
        CouldntSerialize(err: serde_json::Error) { from() }
        InvalidFrom(err: &'static str)
        AttachmentIssue(err: &'static str)
        InvalidUtf8(err: std::string::FromUtf8Error) { from() }
        NoSenderDomain(err: &'static str, email: String)
        NoDkimForDomain(err: &'static str, email: String)
        DkimKeyDecodeFailed(err: &'static str, filename: String)
        TooManyHeaders(err: &'static str)
        MissingHeader(err: &'static str)
        API(err: u16, text: String)
    }
}

/// picks out content type and subtype into regular mimetype string
fn stringify_content_type(ct: &mail_parser::ContentType) -> String {
    let ctype = ct.ctype();
    let mut ctlen = ctype.len();

    let subtype = ct.subtype();
    if let Some(subtype_inner) = subtype {
        ctlen += 1 + subtype_inner.len();
    }

    let mut content_type = String::with_capacity(ctlen);
    content_type.push_str(ctype);
    if let Some(inner_subtype) = subtype {
        content_type.push('/');
        content_type.push_str(inner_subtype);
    }

    content_type
}

fn flatten_addresses(v: &Vec<HeaderValue>) -> Vec<Address> {
    v.iter()
        .flat_map(|headerval| {
            headerval
                .clone()
                .into_address()
                .expect("header value was not an address D:") // TODO: expect nothing!!
                .iter()
                .cloned()
                .collect::<Vec<mail_parser::Addr>>()
        })
        .map(|addr: mail_parser::Addr| Address {
            name: addr.name.clone().map(|name| name.into_owned()),
            // TODO: expect nothing!!:
            email: addr
                .address
                .clone()
                .map(|email| email.into_owned())
                .expect("email was null?!? D:"),
        })
        .collect()
}

#[tokio::main]
async fn main() -> Result<(), MainError> {
    simplelog::TermLogger::init(
        match cfg!(debug_assertions) {
            true => simplelog::LevelFilter::Trace,
            false => simplelog::LevelFilter::Warn,
        },
        simplelog::Config::default(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Never,
    )
    .expect("couldn't init sinplelog::TermLogger");
    let mut buf = Vec::with_capacity(8192);
    let stdin_handle = std::io::stdin();
    let mut stdin = stdin_handle.lock();
    stdin.read_to_end(&mut buf)?;
    let parser = mail_parser::MessageParser::default();
    let msg = parser
        .parse(&buf)
        .ok_or(MainError::NoHeaders("message has no headers"))?;

    #[cfg(debug_assertions)]
    {
        for header in msg.headers() {
            if headers::FORBIDDEN.contains(&header.name) {
                log::trace!("\x1b[31m{}:\x1b[0m {:?}", header.name, header.value);
            }
        }
        for header in msg.headers() {
            if !headers::FORBIDDEN.contains(&header.name) {
                log::trace!("\x1b[32m{}\x1b[0m: {:?}", header.name, header.value);
            }
        }
    }

    let from = match msg.from() {
        Some(addr) => {
            let addresses = match addr {
                mail_parser::Address::Group(group) => {
                    log::error!(
                        "error: looking for single From address, got group: {:?}",
                        group
                    );
                    return Err(MainError::InvalidFrom(
                        "'From' address is a group. this is unsupported",
                    ));
                }
                mail_parser::Address::List(list) => list,
            };
            if addresses.len() > 1 {
                return Err(MainError::InvalidFrom(
                    "'From' address is a list of addresses. this is unsupported. supply only a single address",
                ));
            }
            let address = addresses
                .first()
                .ok_or(MainError::InvalidFrom("'From' header appears empty"))?;
            Address {
                name: address.name().map(|cowstr| cowstr.to_owned()),
                email: address.address().map(|cowstr| cowstr.to_owned()).ok_or(
                    MainError::InvalidFrom("'From' header appears to be missing an email address"),
                )?,
            }
        }
        None => return Err(MainError::InvalidFrom("'From' address missing")),
    };

    let sender_domain: String = from
        .email
        .clone()
        .split('@')
        .next_back()
        .ok_or(MainError::NoSenderDomain(
            "sender email isn't an email address",
            from.email.clone(),
        ))?
        .to_string();

    let keyfilename = std::path::PathBuf::from(format!("/etc/mail/dkim/{}.key.pem", sender_domain));
    let keyfile_exists = keyfilename.try_exists().map_err(|_| MainError::NoDkimForDomain(
        "no dkim key available for sender domain. error when attempting to identify whether key file was readable",
        keyfilename.to_string_lossy().into_owned()
    ))?;
    if !keyfile_exists {
        return Err(MainError::NoDkimForDomain(
            "no dkim key available for sender fomain. key file does not exist or is not readable.",
            keyfilename.to_string_lossy().into_owned(),
        ));
    }

    let dkim = DkimInfo {
        dkim_domain: sender_domain.clone(),
        dkim_private_key: {
            let mut pem_file = std::fs::File::open(&keyfilename)?;
            let pem_file_metadata = pem_file.metadata()?;
            let pem_file_len = pem_file_metadata.len() as usize;
            let mut pem_file_contents = String::with_capacity(pem_file_len);
            pem_file.read_to_string(&mut pem_file_contents)?;

            const HEADER: &str = "-----BEGIN PRIVATE KEY-----\n";
            const FOOTER: &str = "-----END PRIVATE KEY-----\n";
            if !pem_file_contents.starts_with(HEADER) {
                return Err(MainError::DkimKeyDecodeFailed(
                    "dkim key file missing or incorrect pem header",
                    keyfilename.to_string_lossy().into_owned(),
                ));
            }
            if !pem_file_contents.ends_with(FOOTER) {
                return Err(MainError::DkimKeyDecodeFailed(
                    "dkim key file missing or incorrect pem footer",
                    keyfilename.to_string_lossy().into_owned(),
                ));
            }

            let private_key = pem_file_contents
                .chars()
                .skip(HEADER.len())
                .take(pem_file_len - HEADER.len() - FOOTER.len())
                .filter(|c| *c != '\n' && *c != '\r');
            private_key.collect::<String>()
        },
        dkim_selector: String::from(dkim_selector()),
    };

    let mut forbidden_headers = HashMap::<_, Vec<HeaderValue>>::new();
    msg.headers()
        .iter()
        .filter(|header| headers::FORBIDDEN.contains(&header.name))
        .for_each(|header| {
            let value = header.value.clone();
            if forbidden_headers.contains_key(&header.name) {
                let header_vec = forbidden_headers.get_mut(&header.name).unwrap();
                header_vec.push(value);
                return;
            }
            let header_vec = vec![value];
            forbidden_headers.insert(&header.name, header_vec);
        });
    let allowed_headers: HashMap<_, _> = msg
        .headers_raw()
        .filter(|header| !headers::FORBIDDEN.contains(&header.0.into()))
        .map(|header| (String::from(header.0), String::from(&header.1[1..])))
        .collect();

    let subject = forbidden_headers
        .get(&HeaderName::Subject)
        .ok_or(MainError::MissingHeader("need a Subject!"))?;
    let subject = match subject.len() {
        0 => unreachable!("no subject, even after checking for subject"),
        2.. => return Err(MainError::TooManyHeaders("must have only one Subject!")),
        1 => subject[0].clone(),
    };
    let subject = match subject.into_text() {
        None => return Err(MainError::MissingHeader("Subject is empty or missing!")),
        Some(text) => text.into_owned(),
    };

    let body = MailChannelsBody {
        attachments: msg
            .attachments()
            .map(|attachment| match attachment.attachment_name() {
                Some(filename) => Ok(Attachment {
                    filename: filename.to_string(),
                    mimetype: String::from("text/plain"),
                    content: attachment.contents().to_vec(),
                }),
                None => Err(MainError::AttachmentIssue("attachment is missing filename")),
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)?,
        content: msg
            .html_bodies()
            .map(|body| {
                Ok(Content {
                    template_type: None,
                    value: String::from_utf8(body.contents().to_vec())?,
                    content_type: body.content_type().map(stringify_content_type).ok_or(
                        MainError::AttachmentIssue("presumed html body missing content type"),
                    )?,
                })
            })
            .chain(msg.text_bodies().map(|body| {
                Ok(Content {
                    template_type: None,
                    value: String::from_utf8(body.contents().to_vec())?,
                    content_type: body.content_type().map(stringify_content_type).ok_or(
                        MainError::AttachmentIssue("presumed plain text body missing content type"),
                    )?,
                })
            }))
            .collect::<Result<Vec<Content>, MainError>>()?,
        dkim,
        from,
        headers: match allowed_headers.len() {
            0 => None,
            _ => Some(allowed_headers),
        },
        personalizations: vec![Personalization {
            bcc: forbidden_headers
                .get(&HeaderName::Bcc)
                .map(flatten_addresses),
            cc: forbidden_headers
                .get(&HeaderName::Cc)
                .map(flatten_addresses),
            dkim: None,
            dynamic_template_data: None,
            from: None,
            headers: None,
            reply_to: None,
            subject: None,
            to: forbidden_headers
                .get(&HeaderName::To)
                .map(flatten_addresses)
                .ok_or(MainError::MissingHeader("No recipient!!"))?,
        }],
        reply_to: match forbidden_headers
            .get(&HeaderName::ReplyTo)
            .map(flatten_addresses)
        {
            Some(v) if v.len() > 1 => Err(MainError::TooManyHeaders(
                "should only have one Reply-To address!",
            )),
            Some(mut v) => Ok(Some(v.pop().unwrap())),
            None => Ok(None),
        }?,
        subject,
        tracking_settings: None,
        transactional: None,
    };
    let body = serde_json::to_string(&body)?;
    log::trace!("json body.content: {}", body);
    //todo!("construct mailchannels response body");

    let client = reqwest::Client::new();
    let mut headers = reqwest::header::HeaderMap::new();
    headers
        .insert(reqwest::header::CONTENT_TYPE, "application/json".parse()?)
        .inspect(|x| panic!("map already had Content-Type: {:?}", x));
    headers
        .insert(reqwest::header::ACCEPT, "application/json".parse()?)
        .inspect(|x| panic!("map already had Accept: {:?}", x));
    headers
        .insert("X-Api-Key", api_key().parse()?)
        .inspect(|x| panic!("map already had X-Api-Key: {:?}", x));

    let response = client
        .post("https://api.mailchannels.net/tx/v1/send")
        .headers(headers)
        .body(body)
        .send()
        .await?;
    if response.status() == reqwest::StatusCode::OK {
        log::info!("received sandbox 200 ok");
    } else if response.status() == reqwest::StatusCode::ACCEPTED {
        log::info!("Successfully sent mail.");
    } else {
        log::error!(
            "received non-200 status code {}. mail was probably not sent...",
            response.status()
        );
        return Err(MainError::API(
            response.status().as_u16(),
            response.text().await?,
        ));
    }
    log::trace!("{:?}", response);
    log::trace!("response text:\n--\n{}\n--\n", response.text().await?);
    Ok(())
}
