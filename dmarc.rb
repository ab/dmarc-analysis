#!/usr/bin/env ruby
require 'resolv'
require 'set'
require 'thread'
require 'yaml'

KnownSelfDomains = [
  'groupon.com',
  'airbnb.com',
  'citi.com',
  'cba.com.au',
  'yelp.com',
  'dmarc.bitly.net',
  'wikimedia.org',
  'infusionmail.com',
  'db.com',
  'ebay.com',
  'tagged.com',
  'surveymonkey.com',
  'bet365.com',
  'evernote.com',
].to_set

class DmarcAnalyzer
  def initialize
    @resolver = Resolv::DNS.new
  end

  def generate_report(yaml_file)
    dmarc_data = YAML.load_file(yaml_file)
    dmarc_data.each_pair do |domain, record|
      if record
        if is_dmarc_record?(record)
          mailtos = dmarc_mailtos(record)
          classified = classify_mailtos(domain, mailtos).uniq
          policy = dmarc_record_policy(record)
          puts [domain, policy, classified.join(',')].join("\t")
        else
          puts [domain, 'invalid'].join("\t")
        end
      else
        puts [domain, 'nil'].join("\t")
      end
    end
  end

  def log_info(message)
    puts message
  end

  def resolve_dmarc(domain)
    @resolver.getresource('_dmarc.' + domain,
      Resolv::DNS::Resource::IN::TXT).strings.first
  rescue Resolv::ResolvError => err
    unless err.message.include?('DNS result has no information for')
      raise
    end
    return nil
  end

  def resolve_parallel(domains, num_threads=16)
    queue = Queue.new
    lock = Mutex.new
    results = {}

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
            results[domain] = resolved
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
    parts.grep(/^(rua|ruf)=/).map {|p|
      p.scan(/mailto:([^,]+)/).flatten
    }.flatten
  end

  def classify_mailtos(domain, mailtos)
    mailtos.map {|mailto| classify_mailto(domain, mailto) }
  end

  def classify_mailto(domain, mailto)
    mailto_domain = mailto.split('@', 2).last
    case mailto_domain
    when 'ruf.agari.com', 'rua.agari.com'
      'agari'
    when 'auth.returnpath.net'
      'returnpath'
    when 'ag.dmarcian.com', 'fr.dmarcian.com', 'ag.dmarcian-eu.com', 'fr.dmarcian-eu.com'
      'dmarcian'
    when 'labs.messagebus.com'
      'messagebus'
    when 'ruf.netcraft.com', 'rua.netcraft.com', 'dmarc.netcraft.com'
      'netcraft'
    when 'haspf.com'
      'haspf'
    when 'google.com'
      'self:google'
    when 'bounces.amazon.com'
      'self:amazon'
    when 'service.alibaba.com'
      'self:alibaba'
    when 'yahoo-inc.com'
      'self:yahoo'
    when 'dmarc.postmarkapp.com'
      'postmarkapp'
    when 'rep.dmarcanalyzer.com', 'for.dmarcanalyzer.com'
      'dmarcanalyzer'
    when 'sonicwall.com'
      'self:dell'
    when 'qiye.163.com'
      'self:netease'
    else
      if mailto_domain.include?(domain)
        'self'
      elsif KnownSelfDomains.include?(mailto_domain)
        'self'
      else
        "unknown:#{mailto}"
      end
    end
  end
end

case ARGV[0]
when 'report'
  d = DmarcAnalyzer.new
  d.generate_report(ARGV.fetch(1))
when nil
else
  puts "Unknown command #{ARGV[0]}"
  exit 1
end
