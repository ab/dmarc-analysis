#!/usr/bin/env ruby
require 'resolv'
require 'set'
require 'thread'
require 'yaml'

# This is a mapping from domain name to the names that are considered to be
# "self" hosting DMARC reports. The names may be a list of names or a single
# name. For example, if we see that the xfinity.com DMARC record contains
# mailto records @comcast.net, we treat those as self-hosted DMARC analysis.
SelfDomainMap = {
  'bitly.com' => 'dmarc.bitly.net',
  'commbank.com.au' => 'cba.com.au',
  'deutsche-bank.de' => 'db.com',
  'hi5.com' => 'tagged.com',
  'nps.gov' => 'doi.gov',
  'userapi.com' => 'vk.com',
  'washingtonpost.com' => 'washpost.com',
  'wikipedia.org' => 'wikimedia.org',
  'wufoo.com' => 'surveymonkey.com',
  'xfinity.com' => %w{dmarctest.comcast.net comcast.net},
  'yinxiang.com' => 'evernote.com',
}

# Inverse of SelfDomainMap, used to populate the mapping for properties that
# have many domain names all pointing at the same DMARC mailto domain.
SelfDomainReverseMap = {
  'airbnb.com' => %w{airbnb.ca airbnb.co.uk airbnb.com.au airbnb.de airbnb.es airbnb.fr airbnb.it airbnb.ru},
  'citi.com' => %w{citibank.com citibank.co.in citibankonline.com banamex.com},
  'corp.mail.ru' => %w{ok.ru my.com},
  'ebay.com' => %w{gumtree.pl gumtree.co.za},
  'facebook.com' => %w{messenger.com oculus.com},
  'groupon.com' => %w{groupon.it groupon.co.uk groupon.fr groupon.de livingsocial.com},
  'mercadolibre.com' => %w{mercadolivre.com.br mercadolibre.com.ar mercadolibre.com.mx mercadolibre.com.ve mercadolibre.com.co mercadolivre.com mercadopago.com mercadolibre.com.pe mercadolibre.com.uy},
  'rambler-co.ru' => %w{rambler.ru},
  'service.alibaba.com' => %w{taobao.com tmall.com alipay.com aliexpress.com alibaba.com alibaba-inc.com},
  'yahoo-inc.com' => %w{flickr.com tumblr.com umblr.com staticflickr.com rivals.com yimg.com yahoo.net},
  'yandex.ru' => %w{yandex.ua yandex.kz yandex.com.tr yandex.by yandex.com ya.ru postila.ru},
  'yelp.com' => %w{yelp.ca},
}

SelfDomainReverseMap.each_pair do |mailto_domain, domains|
  domains.each do |d|
    SelfDomainMap[d] ||= []
    SelfDomainMap[d] << mailto_domain
  end
end

class DmarcAnalyzer
  def initialize
    @resolver = Resolv::DNS.new
  end

  def generate_report(yaml_file)
    dmarc_data = YAML.safe_load(File.read(yaml_file))
    dmarc_data.each_pair do |domain, record|
      if record
        if is_dmarc_record?(record)
          mailtos = dmarc_mailtos(record)
          classified = classify_mailtos(domain, mailtos).uniq
          policy = dmarc_record_policy(record)
          puts [domain, policy, classified.join(',')].join("\t")
        else
          puts [domain, 'invalid', ''].join("\t")
        end
      else
        puts [domain, 'DNE', ''].join("\t")
      end
    end
  end

  def log_info(message)
    STDERR.puts message
  end

  def resolve_dmarc(domain)
    @resolver.getresource('_dmarc.' + domain,
      Resolv::DNS::Resource::IN::TXT).strings.join('')
  rescue Resolv::ResolvError => err
    unless err.message.include?('DNS result has no information for')
      raise
    end
    return nil
  end

  def dns_lookup_from_file(filename, out_stream=STDOUT)
    domains = File.read(filename).split

    log_info("Looking up #{domains.length} domains")

    results = resolve_parallel(domains)

    log_info("Finished resolving DMARC records!")

    # rely on ruby hash ordering to keep these in order
    output = {}
    results.sort_by {|row| row.fetch(:index) }.each do |row|
      output[row.fetch(:domain)] = row.fetch(:record)
    end

    YAML.dump(output, out_stream)
  end

  def resolve_parallel(domains, num_threads=16)
    queue = Queue.new
    lock = Mutex.new
    results = []

    domains.each_with_index {|d, i| queue.push([d, i]) }

    threads = (0...num_threads).map do
      Thread.new do
        while true
          begin
            domain, index = queue.pop(true)
          rescue ThreadError
            break
          end

          log_info("#{index} #{domain}:")

          resolved = resolve_dmarc(domain)

          log_info("#{index} #{domain} #{resolved.inspect}")

          lock.synchronize do
            results << {domain: domain, index: index, record: resolved}
          end
        end
      end
    end

    threads.each(&:join)

    return results
  end

  def is_dmarc_record?(record)
    record.downcase.start_with?('v=dmarc')
  end

  def dmarc_record_parts(record)
    record.split(';').map(&:strip)
  end

  def dmarc_record_policy(record)
    parts = dmarc_record_parts(record)
    parts.grep(/^p=/).map {|p| p.split('=', 2).last }.join('/')
  end

  def dmarc_mailtos(record)
    parts = dmarc_record_parts(record)
    parts.grep(/^(rua|ruf)\s*=\s*/).map {|p|
      p.scan(/mailto:([^,!]+)/).flatten
    }.flatten
  end

  def classify_mailtos(domain, mailtos)
    mailtos.map {|mailto| classify_mailto(domain, mailto) }
  end

  def classify_mailto(domain, mailto)
    domain = domain.downcase
    mailto = mailto.downcase

    mailto_domain = mailto.split('@', 2).last
    case mailto_domain
    when 'ruf.agari.com', 'rua.agari.com'
      'agari'
    when 'auth.returnpath.net'
      'returnpath'
    when 'ag.dmarcian.com', 'fr.dmarcian.com', 'ag.dmarcian-eu.com', 'fr.dmarcian-eu.com'
      'dmarcian'
    when 'cyberint.com'
      'cyberint'
    when 'dmarc.250ok.net', 'dmarc.250ok.com', '250ok.com'
      '250ok.com'
    when 'labs.messagebus.com'
      'messagebus'
    when 'ruf.netcraft.com', 'rua.netcraft.com', 'dmarc.netcraft.com'
      'netcraft'
    when 'emaildefense.proofpoint.com'
      'proofpoint'
    when 'haspf.com'
      'haspf'
    when 'dmeu.easysol.net', 'easysol.net', 'dm.easysol.net'
      'easysolutions'
    when 'google.com'
      'self:google'
    when 'bounces.amazon.com'
      if domain.start_with?('amazon.')
        'self:amazon'
      else
        "unknown:#{mailto}"
      end
    when 'dmarc.postmarkapp.com'
      'postmarkapp'
    when 'rep.dmarcanalyzer.com', 'for.dmarcanalyzer.com'
      'dmarcanalyzer'
    when 'qiye.163.com'
      'self:netease'
    when 'vali.email', 'valimail.com'
      'valimail'
    when 'mailinblue.com', 'sendinblue.com'
      'sendinblue'
    when 'datafeeds.phishlabs.com'
      'phishlabs'
    when 'mxtoolbox.dmarc-report.com', 'forensics.dmarc-report.com', 'dmarc-report.com'
      'mxtoolbox'
    else
      if mailto_domain.include?(domain)
        # this heuristic is inexact but still useful
        'self'
      elsif SelfDomainMap.include?(domain) \
            && Array(SelfDomainMap.fetch(domain)).include?(mailto_domain)
        # check explicit self domain mapping
        'self'
      else
        "unknown:#{mailto}"
      end
    end
  end
end

def usage
  STDERR.puts <<-EOM
DMARC TXT record slicer and analyzer.

usage: #{$0} report DNS_YAML_FILE
  Generate a TSV report on stdout analyzing the DMARC TXT records contained in
  DNS_YAML_FILE, which may be generated by the resolve sub command.

usage: #{$0} resolve DOMAIN_LIST

  Generate a YAML report on stdout getting the raw DMARC TXT records for each
  domain listed in DOMAIN_LIST, which should be a newline separated list of
  domain names.
  EOM
end

def main
  case ARGV[0]
  when 'report'
    d = DmarcAnalyzer.new
    d.generate_report(ARGV.fetch(1))
  when 'resolve'
    d = DmarcAnalyzer.new
    d.dns_lookup_from_file(ARGV.fetch(1))
  when nil
    usage
    exit 1
  else
    STDERR.puts "Unknown command #{ARGV[0]}"
    usage
    exit 1
  end
end

if __FILE__ == $0
  main
end
