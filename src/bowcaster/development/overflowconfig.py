import ConfigParser
from bowcaster.common.support import Logging
from bowcaster.common.support import Endianness
from bowcaster.development.overflowbuilder import RopGadget,PayloadSection,EncodedPayloadSection
class OverflowConfig(object):
    pass

class OverflowConfigGenerator(object):
    def _init_main_section(self,overflow_buffer):
        conf=self.config
        main_section=("Overflow Description")
        conf.add_section(main_section)
        arch=overflow_buffer.arch
        endianness=overflow_buffer.endianness
        endian_obj=Endianness(endianness)
        endianness_name=endian_obj.name
        
        os=overflow_buffer.os
        conf.set(main_section,"arch",arch)
        conf.set(main_section,"os",os)
        conf.set(main_section,"endianness",endianness_name)
        
    
    def _handle_encoded_payload(self,encoded,section_name):
        conf=self.config
        self.logger.LOG_DEBUG("Processing encoded payload.")
        conf.add_section(section_name)
        for k,v in encoded.details.items():
            if k == "payloads":
                payload_count = 0
                for details in v:
                    payload_count+=1
                    for k,v in details.items():
                        conf.set(section_name,"%s_%d" % (k,payload_count),v)
            else:
                conf.set(section_name,k,v)                   
        
    def _init_overflow_sections(self,overflow_buffer):
        sections=overflow_buffer.overflow_sections
        conf=self.config
        
        known_sections=[RopGadget,PayloadSection,EncodedPayloadSection]
        
        section_count=0
        for section in sections:
            if not section.__class__ in known_sections:
                continue
            else:
                print section.__class__.__name__
                
            section_count += 1
            section_name="Section %d" % section_count
            if section.__class__ == EncodedPayloadSection:
                self._handle_encoded_payload(section,section_name)
                continue
            
            conf.add_section(section_name)
            if section.__class__.__name__ == "RopGadget":
                if section.details["type"] != "RopGadget":
                    self.logger.LOG_WARN("WTF: %s" % section.details["type"])
                    raise Exception()
            
            if section.details["type"] == "OverflowSection":
                self.logger.LOG_WARN("WTF.")
                self.logger.LOG_DEBUG("%s" % section.__class__.__name__)
                raise Exception()
            
            for k,v in section.details.items():
                self.logger.LOG_DEBUG("got section key: %s" % k)
                conf.set(section_name,k,v)
        
    def __init__(self,overflow_buffer,logger=None):
        if not logger:
            logger=Logging()
        self.logger=logger
        config=ConfigParser.RawConfigParser()
        self.config=config
        self._init_main_section(overflow_buffer)
        self._init_overflow_sections(overflow_buffer)
