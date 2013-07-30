import sys
import types
import ConfigParser
import traceback
from collections import OrderedDict
#from ..common.support import class_by_name
from bowcaster.common.support import Logging
from bowcaster.common.support import LittleEndian,BigEndian
from bowcaster.development.overflowbuilder import OverflowBuffer,RopGadget,PayloadSection,EncodedPayloadSection
from bowcaster.payloads.mips import ConnectbackPayload
from bowcaster.encoders import *

def class_by_name(name):
    """
    got this from stackoverflow :-/
    http://stackoverflow.com/questions/1176136/convert-string-to-python-class-object
    """
    try:
        identifier=getattr(sys.modules[__name__],name)
    except AttributeError:
        raise NameError("%s doesn't exist." % name)
    if not isinstance(identifier,(types.ClassType,types.TypeType)):
        raise TypeError("%s is not a class." % name)
    return identifier
    

MAIN_SECTION="Overflow Description"

class OverflowConfigException(Exception):
    def __init__(self,message,details=None):
        self.message=message
        if details:
            self.details=details

class ConfigAddress(object):
    def __init__(self,address,base=0):
        address=int(address,base)
        if address < 0 or address > 0xffffffff:
            raise OverflowConfigException("Address %d out of 32-bit unsigned range." % address)
        self.address=address
    
    def __int__(self):
        return self.address

class ConfigBadchars(list):
    def __init__(self,badchar_string):
        super(self.__class__,self).__init__()
        badints=badchar_string.split(',')
        for bad in badints:
            badint=int(bad,0)
            self.append(chr(badint))

class ConfigEndianness(object):
    Names={}
    Names[BigEndian]="BigEndian"
    Names[LittleEndian]="LittleEndian"
    
    @classmethod
    def from_name(cls,name):
        obj=None
        for n in cls.Names:
            if name == cls.Names[n]:
                obj=cls(n)
                break
        if not obj:
            raise Exception("Endianness for %s name not found" % name)
        
        return obj
        
    def __init__(self,endianness):
        self.value=endianness
        self.name=self.__class__.Names[endianness]


class OverflowConfigParser(object):
    def _gadget_section(details):
        if details["type"] != "RopGadget":
            raise OverflowConfigException("Wrong type specified: %s. Expecting %s." % (details["type"],"RopGadget"))
        endianness=details["endianness"]
        
        offset=int(details["offset"],0)
        rop_address=ConfigAddress(details["rop_address"],16)
        description=details["description"]
        base_address=ConfigAddress(details["base_address"],16)
        badchars=details["bad characters"]
        
        section=RopGadget(endianness,
                         offset,
                         int(rop_address),
                         description=description,
                         base_address=int(base_address),
                         badchars=badchars)
        return section
        
    def _payload_section(details):
        pass
    
    def _encoded_payload_section(details):
        if details["type"] != "EncodedPayloadSection":
            raise OverflowConfigException("Wrong type specified: %s. Expecting %s. " % 
                                                (details["type"],"EncodedPayloadSection"))
        offset=int(details["offset"],0)
        description=details["description"]
        
        encoder_class=details["encoder_class"]
        payload_sections=details["payloads"]
        payloads_to_encode=[]
        for k,v in payload_sections.items():
            payload_details=v
            payload_class=class_by_name(payload_details["payload_class"])
            p=payload_class.reconstitute(payload_details)
            payloads_to_encode.append(p)
        
        details["payloads"]=payloads_to_encode
        encoded_payload_class=class_by_name(details["encoder_class"])
        encoded_payload=encoded_payload_class.reconstitute(details)
        
        section=EncodedPayloadSection(offset,encoded_payload,description=description)
        
        return section
        
    KnownOverflowSections={"RopGadget":_gadget_section,
                        "PayloadSection":_payload_section,
                        "EncodedPayloadSection":_encoded_payload_section}

    def _group_encoded_payloads(self,all_sections):
        logger=self.logger
        encoded_payloads=OrderedDict()
        logger.LOG_DEBUG("_group_encoded_paylaods()")
        #loop over all_sections and pull out encoder
        #sections into a separate dict.
        for section,details in all_sections.items():
            if details.has_key("encoder_class"):
                logger.LOG_DEBUG("Found encoder section: %s" % section)
                encoded_payloads[section]=details
        
        #for each encoder, get its list of payloads,
        for section,details in encoded_payloads.items():
            logger.LOG_DEBUG("Parsing payloads for encoder section: %s" % section)
            payload_string=details["payloads"]
            payload_sections=payload_string.split(',')
            payloads={}
            
            #remove each payload from all_sections, store
            #it in a dict
            for ps in payload_sections:
                logger.LOG_DEBUG("Payload section: %s" % ps)
                payload_details=all_sections.pop(ps)
                payloads[ps]=payload_details
            
            #replace the encoder's
            #"payloads" comma-separated list with this
            #dictionary of payload sections.
            details["payloads"]=payloads
    
    def _build_sections(self,config_sections):
        logger=self.logger
        section_list=[]
        cls=self.__class__
        for section,details in config_sections.items():
            try:
                section_type=details["type"]
                try:
                    handler=cls.KnownOverflowSections[section_type]
                    logger.LOG_DEBUG("handler found for type: %s. %s" % (section_type,str(handler)))
                    section_list.append(handler(details))
                except KeyError as e:
                    traceback.print_exc()
                    raise
                    logger.LOG_WARN("Exception: %s" % str(e))
                    logger.LOG_WARN("No handler for type: %s" % section_type)
                    
            except KeyError as e:
                if str(e)=='type':
                #no "type" for Overflow Description section
                    pass
                    
        return section_list
    
    def _parse_main_section(self):
        self.arch=self.config.get(MAIN_SECTION,"arch")
        self.os=self.config.get(MAIN_SECTION,"os")
        self.endianness=ConfigEndianness.from_name(self.config.get(MAIN_SECTION,"endianness"))
        self.badchars=ConfigBadchars(self.config.get(MAIN_SECTION,"bad characters"))
        self.length=int(self.config.get(MAIN_SECTION,"buffer length"),0)
    
    
    def __init__(self,configfile):
        self.logger=Logging()
        self.config=ConfigParser.RawConfigParser()
        self.config.read(configfile)
        sections=self.config.sections()
        all_sections=OrderedDict()
        self._parse_main_section()
        for section in sections:
            details=dict(self.config.items(section))
            if not details.has_key("endianness"):
                details["endianness"]=self.endianness.value
            if not details.has_key("bad characters"):
                details["bad characters"]=self.badchars
            all_sections[section]=details
        
        self._group_encoded_payloads(all_sections)
        #print all_sections
        self.section_list=self._build_sections(all_sections)
        print self.section_list
        self.overflow_buf=OverflowBuffer(self.endianness.value,
                                         self.length,
                                         overflow_sections=self.section_list,
                                         badchars=self.badchars)

class OverflowConfigGenerator(object):
    def _init_main_section(self,overflow_buffer):
        conf=self.config
        conf.add_section(MAIN_SECTION)
        arch=overflow_buffer.arch
        endianness=overflow_buffer.endianness
        endian_obj=ConfigEndianness(endianness)
        endianness_name=endian_obj.name
        
        os=overflow_buffer.os
        conf.set(MAIN_SECTION,"arch",arch)
        conf.set(MAIN_SECTION,"os",os)
        conf.set(MAIN_SECTION,"endianness",endianness_name)
        conf.set(MAIN_SECTION,"buffer length","%d" % len(overflow_buffer))
    
    def _handle_payload(self,details):
        conf=self.config
        section_name = "Section %d" % self.section_count
        conf.add_section(section_name)
        for k,v in details.items():
            conf.set(section_name,k,v)
        
        return section_name
        
    def _handle_encoded_payload(self,encoded,section_name):
        conf=self.config
        self.logger.LOG_DEBUG("Processing encoded payload.")
        conf.add_section(section_name)
        payload_string=""
        for k,v in encoded.details.items():
            if k == "payloads":
                for details in v:
                    self.section_count+=1
                    pl_section_name=self._handle_payload(details)
                    payload_string=payload_string+"%s," % pl_section_name
                if len(payload_string) > 0:
                    payload_string=payload_string.strip(',')
                    conf.set(section_name,"payloads",payload_string)
            else:
                conf.set(section_name,k,v)

    def _merge_badchars(self,badchars):
        if not self.badchars:
            self.badchars=badchars
        else:
            self.badchars=list(set(self.badchars+badchars))
        badchar_string=""
        print self.badchars
        print badchars
        print "%d badchars" % len(self.badchars)
        
        for char in self.badchars:
            print "%#04x" % ord(char)
        
        for char in self.badchars[:-1]:
#            print type(char)
            badchar_string += "%#04x," % ord(char)
        
        if len(self.badchars) > 0:
            print badchar_string
            print self.badchars[-1]
            print ord(self.badchars[-1])
            
            badchar_string += "%#04x" % ord(self.badchars[-1])
        
        print "badchar string: %s" % badchar_string
        self.badchar_string=badchar_string
            
        
    def _init_overflow_sections(self,overflow_buffer):
        sections=overflow_buffer.overflow_sections
        conf=self.config
        
        known_sections=[RopGadget,PayloadSection,EncodedPayloadSection]
        
        self.section_count=0
        for section in sections:
            if not section.__class__ in known_sections:
                continue
            else:
                print section.__class__.__name__
            self._merge_badchars(section.badchars)
            self.section_count += 1
            section_name="Section %d" % self.section_count
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
        self.badchars=None
        self.badchars=self._merge_badchars(overflow_buffer.badchars)
        self._init_main_section(overflow_buffer)
        self._init_overflow_sections(overflow_buffer)
        self.config.set("Overflow Description","bad characters",self.badchar_string)
