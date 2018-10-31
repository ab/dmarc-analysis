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
  'federalreserve.gov' => 'frb.gov',
  'hi5.com' => 'tagged.com',
  'mchenrycountyil.gov' => 'co.mchenry.il.us',
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
  'abilenetx.com' => %w{abilenetx.gov},
  'airbnb.com' => %w{airbnb.ca airbnb.co.uk airbnb.com.au airbnb.de airbnb.es airbnb.fr airbnb.it airbnb.ru},
  'cbp.dhs.gov' => %w{cbp.gov evus.gov},
  'cfpb.gov' => %w{consumerfinance.gov},
  'citi.com' => %w{citibank.com citibank.co.in citibankonline.com banamex.com},
  'cns.gov' => %w{americorps.gov vistacampus.gov presidentialserviceawards.gov},
  'consumersentinel.gov' => %w{econsumer.gov ftccomplaintassistant.gov},
  'corp.mail.ru' => %w{ok.ru my.com},
  'cpsc.gov' => %w{poolsafely.gov recalls.gov saferproducts.gov},
  'doc.gov' => %w{2020census.gov aviationweather.gov bea.gov bldrdoc.gov census.gov climate.gov firstnet.gov gps.gov manufacturing.gov mbda.gov noaa.gov ntis.gov time.gov weather.gov},
  'doe.gov' => %w{energy.gov},
  'doi.gov' => %w{usgs.gov fws.gov blm.gov usbr.gov nationalmap.gov nifc.gov nps.gov sciencebase.gov indianaffairs.gov boem.gov bia.gov bsee.gov mrlc.gov fgdc.gov geomac.gov volunteer.gov osmre.gov alaskacenters.gov anstaskforce.gov geoplatform.gov klamathrestoration.gov onrr.gov},
  'dol.gov' => %w{apprenticeship.gov benefits.gov dol-esa.gov msha.gov},
  'dot.gov' => %w{bts.gov nhtsa.gov safercar.gov transportation.gov},
  'ebay.com' => %w{gumtree.pl gumtree.co.za},
  'ed.gov' => %w{childstats.gov studentloans.gov fafsa.gov g5.gov nagb.gov nationsreportcard.gov},
  'epa.gov' => %w{airnow.gov regulations.gov},
  'faa.gov' => %w{faasafety.gov},
  'facebook.com' => %w{messenger.com oculus.com},
  'fbi.gov' => %w{cjis.gov nicsezcheckfbi.gov},
  'fcc.gov' => %w{broadbandmap.gov},
  'fda.hhs.gov' => %w{fda.gov},
  'fema.dhs.gov' => %w{disasterassistance.gov fema.gov floodsmart.gov ready.gov},
  'fhfa.gov' => %w{harp.gov},
  'frb.gov' => %w{ffiec.gov uscurrency.gov},
  'fs.fed.us' => %w{nwcg.gov},
  'ftc.gov' => %w{consumer.gov consumidor.gov},
  'groupon.com' => %w{groupon.it groupon.co.uk groupon.fr groupon.de livingsocial.com},
  'gsa.gov' => %w{18f.gov acquisition.gov acus.gov cbca.gov cfo.gov challenge.gov cio.gov code.gov cpars.gov data.gov digital.gov digitaldashboard.gov eac.gov esrs.gov everykidinapark.gov fai.gov fbo.gov fedramp.gov fpds.gov fsd.gov govsales.gov gsaadvantage.gov gsaauctions.gov idmanagement.gov performance.gov plainlanguage.gov reginfo.gov sam.gov search.gov section508.gov usa.gov vote.gov},
  'hartford.gov' => %w{hartfordschools.org},
  'hq.dhs.gov' => %w{cbp.gov e-verify.gov fletc.gov secretservice.gov tsa.gov uscis.gov},
  'hq.doe.gov' => %w{energy.gov},
  'ice.dhs.gov' => %w{ice.gov},
  'mail.house.gov' => %w{jct.gov},
  'mail.nasa.gov' => %w{globe.gov scijinks.gov},
  'mail.pci.gov' => %w{whitehouse.gov},
  'mecknc.gov' => %w{mecklenburgcountync.gov},
  'mercadolibre.com' => %w{mercadolivre.com.br mercadolibre.com.ar mercadolibre.com.mx mercadolibre.com.ve mercadolibre.com.co mercadolivre.com mercadopago.com mercadolibre.com.pe mercadolibre.com.uy},
  'nist.gov' => %w{bldrdoc.gov manufacturing.gov time.gov},
  'nrel.gov' => %w{smartgrid.gov},
  'nsf.gov' => %w{science360.gov research.gov},
  'occ.treas.gov' => %w{occ.gov},
  'ocio.usda.gov' => %w{ars-grin.gov biopreferred.gov choosemyplate.gov invasivespeciesinfo.gov nutrition.gov nwcg.gov},
  'ofdp.irs.gov' => %w{tax.gov irsvideos.gov},
  'omb.gov' => %w{itdashboard.gov max.gov},
  'opm.gov' => %w{applicationmanager.gov usajobs.gov usastaffing.gov usalearning.gov employeeexpress.gov fedshirevets.gov chcoc.gov},
  'orau.org' => %w{orau.gov},
  'ornl.gov' => %w{fueleconomy.gov},
  'other.mail.census.gov' => %w{2020census.gov},
  'pnnl.gov' => %w{pnl.gov},
  'rambler-co.ru' => %w{rambler.ru},
  'sec.gov' => %w{investor.gov},
  'service.alibaba.com' => %w{taobao.com tmall.com alipay.com aliexpress.com alibaba.com alibaba-inc.com},
  'ssa.gov' => %w{socialsecurity.gov},
  'state.gov' => %w{america.gov foreignassistance.gov osac.gov pepfar.gov usconsulate.gov usembassy.gov usmission.gov},
  'trade.gov' => %w{export.gov privacyshield.gov},
  'treasury.gov' => %w{cdfifund.gov eftps.gov financialresearch.gov fincen.gov helpwithmybank.gov makinghomeaffordable.gov moneyfactory.gov moneyfactorystore.gov mymoney.gov occ.gov pay.gov treas.gov treasurydirect.gov ttb.gov ttbonline.gov usaspending.gov usmint.gov},
  'usaid.gov' => %w{pmi.gov},
  'uscg.mil' => %w{uscg.gov},
  'usda.gov' => %w{ars-grin.gov biopreferred.gov choosemyplate.gov invasivespeciesinfo.gov nutrition.gov nwcg.gov},
  'usdoj.gov' => %w{ada.gov atf.gov atfonline.gov bjs.gov bop.gov dea.gov ic3.gov justice.gov justthinktwice.gov lep.gov namus.gov nationalgangcenter.gov ncirc.gov ncjrs.gov nicic.gov nij.gov nsopw.gov ojp.gov ovcttac.gov smart.gov ucrdatatool.gov usmarshals.gov vcf.gov vehiclehistory.gov},
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
    when 'rua.dmp.cisco.com', 'ruf.dmp.cisco.com'
      'cisco'
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
    when 'vali.email', 'valimail.com', 'valigov.email'
      'valimail'
    when 'mailinblue.com', 'sendinblue.com'
      'sendinblue'
    when 'datafeeds.phishlabs.com'
      'phishlabs'
    when 'mxtoolbox.dmarc-report.com', 'forensics.dmarc-report.com', 'dmarc-report.com'
      'mxtoolbox'
    when 'dmarc.cyber.dhs.gov'
      'dhs-nppd'
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
