#include <vector>
#include <string>
#include <fstream>
#include <sstream>

#include <osquery/core.h>
#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/events/linux/inotify.h"
#include "osquery/tables/events/event_utils.h"

namespace osquery {

/**
 * @brief Track time, action changes to /var/log/perf/tlb.log
 *
 * This is mostly an example EventSubscriber implementation.
 */
class TlbEventSubscriber : public EventSubscriber<INotifyEventPublisher> {
 public:
  Status init() override {
    time = 0;
    configure();
    return Status(0);
  }

  /// Walk the configuration's file paths, create subscriptions.
  void configure() override;

  /**
   * @brief This exports a single Callback for INotifyEventPublisher events.
   *
   * @param ec The EventCallback type receives an EventContextRef substruct
   * for the INotifyEventPublisher declared in this EventSubscriber subclass.
   *
   * @return Was the callback successful.
   */
  Status Callback(const ECRef& ec, const SCRef& sc);
 private:
  float time;
};

/**
 * @brief Each EventSubscriber must register itself so the init method is
 *called.
 *
 * This registers TlbEventSubscriber into the osquery EventSubscriber
 * pseudo-plugin registry.
 */
REGISTER(TlbEventSubscriber, "event_subscriber", "tlb_events");

void TlbEventSubscriber::configure() {
  // Clear all monitors from INotify.
  // There may be a better way to find the set intersection/difference.
  removeSubscriptions();

  std::string file("/var/log/perf/tlb.log");
  VLOG(1) << "Added file event listener to: " << file;
  auto sc = createSubscriptionContext();
  sc->recursive = 0;
  sc->path = file;
  sc->mask = kFileDefaultMasks;
  subscribe(&TlbEventSubscriber::Callback, sc);
}

Status TlbEventSubscriber::Callback(const ECRef& ec, const SCRef& sc) {
  if (ec->action.empty()) {
    return Status(0);
  }

  Row r;
  std::string line;

  r["action"] = ec->action;
  r["target_path"] = ec->path;
  r["transaction_id"] = INTEGER(ec->event->cookie);

  std::ifstream fhandle(ec->path);
  auto split = [](std::string &s, char delim,
      std::vector<std::string> &elems) {
        std::stringstream ss(s);
        std::string elem;

        while (std::getline(ss, elem, delim)) {
          elems.push_back(elem);
        }
      };

  if (fhandle.is_open()) {
    while (std::getline(fhandle, line)) {
      std::vector<std::string> splitrow;

      split(line, ',', splitrow);

      float event_time = stof(splitrow[0]);
      if (time > event_time) {
        continue;
      }

      if (splitrow[3].compare("dTLB-loads") == 0) {
        r["dtlb_loads"] = std::move(splitrow[1]);
      } else if (splitrow[3].compare("dTLB-load-misses") == 0) {
        r["dtlb_load_misses"] = std::move(splitrow[1]);
      }

      time = stof(splitrow[0]);
    }
    fhandle.close();
  }

  add(r);
  return Status(0, "OK");
}
}
