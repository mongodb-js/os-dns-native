#include <napi.h>

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>

namespace {

enum class QueryClass {
  IN = ns_c_in
};

enum class QueryType {
  A = ns_t_a,
  AAAA = ns_t_aaaa,
  SRV = ns_t_srv,
  TXT = ns_t_txt,
  CNAME = ns_t_cname
};

class ResourceRecord {
 public:
  ResourceRecord(ns_msg* msg, size_t initial_pos);

  std::string read(QueryType type) const;

  ResourceRecord(ResourceRecord&&) = default;
  ResourceRecord& operator=(ResourceRecord&&) = default;

 private:
  ResourceRecord(const ResourceRecord&) = delete;
  ResourceRecord& operator=(const ResourceRecord&) = delete;

  std::string asTXT() const;
  std::string asA() const;
  std::string asAAAA() const;
  std::string asCNAME() const;
  std::string asSRV() const;
  std::pair<const uint8_t*, size_t> rawData() const;

  ns_rr record_;
  const uint8_t* start_ = nullptr;
  const uint8_t* end_ = nullptr;
  size_t pos_ = 0;
};

class DNSReponse {
 public:
  DNSReponse(const std::string& search, std::vector<uint8_t>&& raw_data);
  std::vector<ResourceRecord>& records() { return records_; }
  const std::vector<ResourceRecord>& records() const { return records_; }

 private:
  std::vector<uint8_t> raw_data_;
  std::vector<ResourceRecord> records_;
  ns_msg answer_;
};

class DNSController {
 public:
  DNSController();
  ~DNSController();

  DNSReponse Lookup(
      const std::string& name,
      QueryClass cls,
      QueryType type);

 private:
  DNSController(const DNSController&) = delete;
  DNSController& operator=(const DNSController&) = delete;

  struct __res_state state_;
};

ResourceRecord::ResourceRecord(ns_msg* msg, size_t pos)
  : start_(ns_msg_base(*msg)),
    end_(ns_msg_end(*msg)),
    pos_(pos) {
  if (ns_parserr(msg, ns_s_an, pos_, &record_) != 0) {
    throw std::runtime_error(
        std::string("Invalid record ") + std::to_string(pos) +
        " of DNS answer: " + strerror(errno));
  }
}

std::string ResourceRecord::read(QueryType type) const {
  switch (type) {
    case QueryType::A:
      return asA();
    case QueryType::AAAA:
      return asAAAA();
    case QueryType::SRV:
      return asSRV();
    case QueryType::TXT:
      return asTXT();
    case QueryType::CNAME:
      return asCNAME();
  }
  return "";
}

std::string ResourceRecord::asTXT() const {
  const uint8_t* data;
  size_t len;
  std::tie(data, len) = rawData();
  if (len == 0 || data[0] > len - 1) {
    throw std::runtime_error("Invalid DNS TXT record received");
  }
  return std::string(data + 1, data + 1 + data[0]);
}

std::string ResourceRecord::asA() const {
  const uint8_t* data;
  size_t len;
  std::tie(data, len) = rawData();

  if (len != 4) {
    throw std::runtime_error("Invalid DNS A record receive");
  }
  char ipv4[20];
  snprintf(ipv4, sizeof(ipv4), "%d.%d.%d.%d", data[0], data[1], data[2], data[3]);
  return ipv4;
}

std::string ResourceRecord::asAAAA() const {
  const uint8_t* data;
  size_t len;
  std::tie(data, len) = rawData();

  if (len != 16) {
    throw std::runtime_error("Invalid DNS A record receive");
  }
  char ipv6[60];
  snprintf(ipv6, sizeof(ipv6), "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
    data[0], data[1], data[2], data[3],
    data[4], data[5], data[6], data[7],
    data[8], data[9], data[10], data[11],
    data[12], data[13], data[14], data[15]);
  return ipv6;
}

std::string ResourceRecord::asCNAME() const {
  return asTXT(); // Same parser.
}

std::string ResourceRecord::asSRV() const {
  struct SrvHeader {
    uint16_t priority;
    uint16_t weight;
    uint16_t port;
  };
  const uint8_t* data;
  size_t len;
  std::tie(data, len) = rawData();

  if (data < start_ || data + sizeof(SrvHeader) > end_) {
    throw std::runtime_error(std::string("Incorrect result ") +
      std::to_string(pos_) + " of SRV answer: Incorrect result size");
  }
  SrvHeader header;
  memcpy(&header, data, sizeof(header));
  header.port = ntohs(header.port);
  header.priority = ntohs(header.priority);
  header.weight = ntohs(header.weight);

  // Use @ as an invalid hostname character.
  std::string name(8192, '@');

  const int size = dn_expand(start_,
                             end_,
                             data + sizeof(header),
                             &name[0],
                             name.size());

  if (size < 1) {
    throw std::runtime_error(std::string("Incorrect result ") +
      std::to_string(pos_) + " of SRV answer: Invalid hostname format");
  }

  name.resize(name.find('\0'));
  name += ':';
  name += std::to_string(header.port);
  name += ",prio=";
  name += std::to_string(header.priority);
  name += ",weight=";
  name += std::to_string(header.weight);

  return name;
}


std::pair<const uint8_t*, size_t> ResourceRecord::rawData() const {
  return { ns_rr_rdata(record_), ns_rr_rdlen(record_) };
}

DNSReponse::DNSReponse(const std::string& search, std::vector<uint8_t>&& raw_data)
  : raw_data_(std::move(raw_data)) {
  if (ns_initparse(&raw_data_[0], raw_data_.size(), &answer_) != 0) {
    throw std::runtime_error(std::string("Invalid DNS answer for \"") + search + "\"");
  }

  size_t nrecords = ns_msg_count(answer_, ns_s_an);
  if (nrecords == 0) return;

  for (size_t i = 0; i < nrecords; i++) {
    records_.emplace_back(&answer_, i);
  }
}

DNSController::DNSController() {
  errno = 0;
  if (res_ninit(&state_) != 0) {
    throw std::runtime_error(
      std::string("Could not perform DNS lookup, res_ninit() failed: ") +
      strerror(errno));
  }
}

DNSController::~DNSController() {
  res_nclose(&state_);
}

DNSReponse DNSController::Lookup(
    const std::string& name,
    QueryClass cls,
    QueryType type) {
  std::vector<uint8_t> answer(65536);
  h_errno = 0;
  int result = res_nsearch(
    &state_,
    name.c_str(),
    static_cast<int>(cls),
    static_cast<int>(type),
    &answer[0],
    answer.size());
  if (result < 0) {
    throw std::runtime_error(
      std::string("Failed to look up \"") + name + "\": " + hstrerror(h_errno));
  }
  answer.resize(result);
  answer.shrink_to_fit();
  return DNSReponse(name, std::move(answer));
}
#endif

using namespace Napi;


class DNSWorker : public AsyncWorker {
 public:
  DNSWorker(
      Function callback,
      const std::string& name,
      QueryClass cls,
      QueryType type)
    : AsyncWorker(callback, "on-dns-native:DNSWorker"),
      name_(name),
      cls_(cls),
      type_(type) {}

  void Execute() override;
  void OnOK() override;

 private:
  std::vector<std::string> result_;
  std::string name_;
  QueryClass cls_;
  QueryType type_;
};

void DNSWorker::Execute() {
  DNSController controller;
  DNSReponse response = controller.Lookup(name_, cls_, type_);
  for (const ResourceRecord& record: response.records()) {
    result_.emplace_back(record.read(type_));
  }
}

void DNSWorker::OnOK() {
  HandleScope scope(Env());
  Array result = Array::New(Env(), result_.size());
  for (size_t i = 0; i < result_.size(); i++) {
    result[i] = String::New(Env(), result_[i]);
  }
  Callback().Call({Env().Null(), result});
}

void Lookup(const CallbackInfo& args) {
  Function cb = args[3].As<Function>();
  std::string query = args[0].As<String>();
  int cls = args[1].As<Number>();
  int type = args[2].As<Number>();
  DNSWorker* wk = new DNSWorker(
      cb,
      std::move(query),
      static_cast<QueryClass>(cls),
      static_cast<QueryType>(type));
  wk->Queue();
}

} // anonymous namespace

static Object Init(Env env, Object exports) {
  exports["lookup"] = Function::New(env, Lookup);
  return exports;
}

NODE_API_MODULE(os_dns_native, Init)
