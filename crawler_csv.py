from host_node import HostNode
import operator


class CrawlerCSV:
    def __new__(cls, *args, **kwargs):
        return super().__new__(cls)

    def __init__(self):
        self.file_name = ""
        self.save_dir = ""
        self.current_host: HostNode = None

    def write_csv(self):
        this_file = open(self.save_dir + "/" + self.file_name + ".csv", "w")
        self.write_host_info(this_file)
        self.write_emails(this_file)
        self.write_onsite_links(this_file)
        self.write_offsite_links(this_file)
        this_file.close()

    def write_host_info(self, this_file):
        this_file.write("      Domain:," + self.current_host.domain + "\n")
        this_file.write("    In Scope:," + str(self.current_host.is_in_scope) + "\n")
        this_file.write(" Occurrences:," + str(self.current_host.occurrences) + "\n")
        this_file.write("Emails Found:," + str(self.current_host.email_list.total_nodes) + "\n")
        this_file.write(" Links Found:," + str(self.current_host.href_list.total_nodes) + "\n")
        this_file.write("     SHA-256:," + self.current_host.hash + "\n")
        this_file.write("\n")

    def write_emails(self, this_file):
        this_file.write("Email List:," + "\n")
        this_file.write("Occurrences, Address" + "\n")
        email_list = self.current_host.email_list.list
        if len(email_list) != 0:
            for email in email_list:
                this_file.write(str(email.occurrences) + "," + email.address + "\n")

        this_file.write("\n")

    def write_onsite_links(self, this_file):
        this_file.write("On-site Href List:," + "\n")
        this_file.write("Occurrences, Path" + "\n")
        href_list = self.current_host.href_list.list
        on_site_list = []
        if len(href_list) != 0:
            for href in href_list:
                if href.is_offsite is False:
                    on_site_list.append(href)

        on_site_list.sort(key=operator.attrgetter('occurrences'), reverse=True)
        for this_href in on_site_list:
            this_file.write(str(this_href.occurrences) + "," + this_href.location + "\n")

        this_file.write("\n")

    def write_offsite_links(self, this_file):
        this_file.write("Off-site Href List:," + "\n")
        this_file.write("Occurrences, Address" + "\n")
        href_list = self.current_host.href_list.list
        off_site_list = []
        if len(href_list) != 0:
            for href in href_list:
                if href.is_offsite is True:
                    off_site_list.append(href)

        off_site_list.sort(key=operator.attrgetter('occurrences'), reverse=True)
        for this_href in off_site_list:
            this_file.write(str(this_href.occurrences) + "," + this_href.location + "\n")

        this_file.write("\n")
