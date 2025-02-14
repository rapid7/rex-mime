# -*- coding: binary -*-
module Rex
module MIME
class Message

  require 'rex/mime/header'
  require 'rex/mime/part'
  require 'rex/mime/encoding'
  require 'rex/text'

  include Rex::MIME::Encoding

  attr_accessor :header, :parts, :bound, :content


  def initialize(data=nil)
    self.header = Rex::MIME::Header.new
    self.parts = []
    self.bound = "---------------------------#{Rex::Text::rand_text_numeric(30)}"
    self.content = ''
    if data
      head,body = data.split(/\r?\n\r?\n/, 2)

      self.header.parse(head)
      ctype = self.header.find('Content-Type')

      if ctype && ctype[1] && ctype[1] =~ /multipart\/mixed;\s*boundary="?([A-Za-z0-9'\(\)\+\_,\-\.\/:=\?^\s]+)"?/
        self.bound = $1
        chunks = body.to_s.split(/--#{self.bound}(--)?\r?\n?/)
        self.content = chunks.shift.to_s.gsub(/\s+$/, '')
        self.content << "\r\n" unless self.content.empty?

        chunks.each do |chunk|
          break if chunk == "--"
          head,body = chunk.split(/\r?\n\r?\n/, 2)
          part = Rex::MIME::Part.new
          part.header.parse(head)
          part.content = body&.delete_suffix("\r\n")
          self.parts << part
        end
      else
        self.content = body.to_s.gsub(/\s+$/, '') + "\r\n"
      end
    end
  end

  def to
    (self.header.find('To') || [nil, nil])[1]
  end

  def to=(val)
    self.header.set("To", val)
  end

  def from=(val)
    self.header.set("From", val)
  end

  def from
    (self.header.find('From') || [nil, nil])[1]
  end

  def subject=(val)
    self.header.set("Subject", val)
  end

  def subject
    (self.header.find('Subject') || [nil, nil])[1]
  end

  def mime_defaults
    self.header.set("MIME-Version", "1.0")
    self.header.set("Content-Type", "multipart/mixed; boundary=\"#{self.bound}\"")
    self.header.set("Subject", '') # placeholder
    self.header.set("Date", Time.now.strftime("%a,%e %b %Y %H:%M:%S %z"))
    self.header.set("Message-ID",
      "<"+
      Rex::Text.rand_text_alphanumeric(rand(20)+40)+
      "@"+
      Rex::Text.rand_text_alpha(rand(20)+3)+
      ">"
    )
    self.header.set("From", '')    # placeholder
    self.header.set("To", '')      # placeholder
  end


  def add_part(data='', content_type='text/plain', transfer_encoding="8bit", content_disposition=nil)
    part = Rex::MIME::Part.new

    if content_disposition
      part.header.set("Content-Disposition", content_disposition)
    end

    part.header.set("Content-Type", content_type) if content_type

    if transfer_encoding
      part.header.set("Content-Transfer-Encoding", transfer_encoding)
    end

    part.content = data
    self.parts << part
    part
  end

  def add_part_attachment(data, name)
    self.add_part(
      Rex::Text.encode_base64(data, "\r\n"),
      "application/octet-stream; name=\"#{name}\"",
      "base64",
      "attachment; filename=\"#{name}\""
    )
  end


  def add_part_inline_attachment(data, name)
    self.add_part(
      Rex::Text.encode_base64(data, "\r\n"),
      "application/octet-stream; name=\"#{name}\"",
      "base64",
      "inline; filename=\"#{name}\""
    )
  end

  def to_s
    header_string = self.header.to_s

    msg = header_string.empty? ? '' : force_crlf(self.header.to_s + "\r\n")
    msg << force_crlf(self.content + "\r\n") unless self.content.to_s.strip.empty?

    self.parts.each do |part|
      msg << force_crlf("--" + self.bound + "\r\n")
      msg << part.to_s
    end

    msg << force_crlf("--" + self.bound + "--\r\n") if self.parts.length > 0

    msg
  end

end
end
end

