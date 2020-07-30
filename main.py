from kivy.app import App
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.relativelayout import RelativeLayout
from kivy.uix.widget import Widget
from kivy.uix.label import Label
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.recycleview import RecycleView
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
#from kivy.properties import NumericProperty,ObjectProperty
from bsv_mini import bsv
#from kivy.uix.camera import Camera
from kivy.garden.qrcode import QRCodeWidget
from kivy.core.window import Window
from myzbarcam import MyZBarCam
from kivy_garden.xcamera import XCamera
import ast
import re
import os
import json
import sqlalchemy
from sqlalchemy import and_, or_, not_
from sqlalchemy import create_engine, MetaData, Table, Column, Integer, String, Boolean, ForeignKey, UniqueConstraint, bindparam
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import webbrowser
from transaction import get_rawtx_to_pay, create_transaction, sweep, confirm_deposit
from network import broadcast_tx
import time

Base = declarative_base()

class UTXO(Base):
    __tablename__ = 'utxo'
    __table_args__ = (sqlalchemy.schema.UniqueConstraint('txid', 'txindex', name='uix_1'),)
 
    id = Column(Integer, primary_key=True)
    PrivateKey = Column(String)
    txid = Column(String)
    txindex = Column(Integer)
    confirmations = Column(Integer)
    amount = Column(Integer)

class PrivateKeyList(Base):
    __tablename__ = 'privatekey'

    id = Column(Integer, primary_key=True)
    PrivateKey = Column(String)
    Address = Column(String)
    is_activated = Column(Boolean, unique=False)

class TxHistory(Base):
    __tablename__ = 'txhistory'
    
    id = Column(Integer, primary_key=True)
    txid = Column(String)
    amount = Column(Integer)
    rawtx = Column(String)
    is_recieved = Column(Boolean, unique=False)  #True : Recieve  False: Pay


app_path = os.path.dirname(os.path.abspath(__file__))
print(app_path)
engine = create_engine('sqlite:///'+os.path.join(app_path, 'simplewallet.sqlite3'), echo=False)
Session = sessionmaker(bind = engine)
session = Session()

def init_db():
    Base.metadata.create_all(engine)
    ini_prik = bsv()
    session.bulk_insert_mappings(PrivateKeyList,[{'PrivateKey': ini_prik.to_wif(),'Address': ini_prik.address,'is_activated': True}])
    session.commit()

if not os.path.exists(os.path.join(app_path, 'simplewallet.sqlite3')):
    init_db()
    

def get_recieve_address():
    result = session.query(PrivateKeyList).filter_by(is_activated=True).one()
    return result.Address




Window.keyboard_anim_arg = {'d': 0.1,'t':'in_out_expo'}
Window.softinput_mode = 'below_target'

class MainScreen(Screen):
    pass

class MainScreenManage(ScreenManager):
    pass

class HistoryScreen(Screen):
    balance = 0
    def __init__(self, **kwargs):
        super(HistoryScreen, self).__init__(**kwargs)
        result = session.query(UTXO).all()
        utxosets = [item.__dict__.copy() for item in result]
        self.balance = 0
        for item in utxosets:
            self.balance += item['amount']
    
    def update_balance(self):
        result = session.query(UTXO).all()
        utxosets = [item.__dict__.copy() for item in result]
        self.balance = 0
        for item in utxosets:
            self.balance += item['amount']
        self.ids.balance.text = 'Balance: '+str(self.balance) +' sats   (TOUCH TO REFRESH)'
        
    
    def on_press_button(self):
        self.ids.button.text = bsv().address

class QRAddressScreen(Screen):
    address = get_recieve_address()

    def get_new_address(self):
        result = session.query(PrivateKeyList).filter_by(is_activated=True).one()
        result.is_activated = False
        session.add(result)
        prik = bsv()
        session.bulk_insert_mappings(PrivateKeyList,[{'PrivateKey': prik.to_wif(),'Address': prik.address,'is_activated': True}])
        session.commit()
        self.address = get_recieve_address()
        self.ids.qr.data = self.address
        self.ids.recieve_address.text = self.address
        return self.address

    def get_recieve_address(self):
        result = session.query(PrivateKeyList).filter_by(is_activated=True).one()
        return result.Address

    def confirm_button(self):
        address = self.ids.recieve_address.text
        utxosets = confirm_deposit(address)
        key_query = session.query(PrivateKeyList).filter_by(Address=address).one()
        prik = key_query.__dict__.copy()
        print(prik['PrivateKey'])
        for item in utxosets:
            item['PrivateKey'] = prik['PrivateKey']
            query = session.query(UTXO).filter(and_(UTXO.txid==item['txid'],UTXO.txindex==item['txindex'])).all()
            if query:
                print(query[0].__dict__)
                pass
            else:
                session.bulk_insert_mappings(UTXO,[item])
                item['is_recieved'] = True
                session.bulk_insert_mappings(TxHistory,[item])
                session.commit()
            
        


    

    
class AddressListScreen(Screen):
    def resync_button(self):
        keylist = session.query(PrivateKeyList).order_by(PrivateKeyList.id.desc()).all()
        key_address_list = [(key.__dict__['PrivateKey'],key.__dict__['Address']) for key in keylist]
        print(key_address_list)
        session.query(UTXO).delete()
        for key_address in key_address_list:
            prik = key_address[0]
            print(prik)
            address = key_address[1]
            utxosets = confirm_deposit(address)
            if utxosets:
                for item in utxosets:
                    item['PrivateKey'] = prik
                session.bulk_insert_mappings(UTXO,[item])
                session.commit()
            time.sleep(0.5)

class AddressListView(GridLayout):
    
    def __init__(self, **kwargs):
        super(AddressListView, self).__init__(**kwargs)
        
        self.bind(minimum_height=self.setter('height'))
        self.fetch_data_from_database()
        self.display()
        
    def fetch_data_from_database(self):
        result = session.query(PrivateKeyList).order_by(PrivateKeyList.id.desc()).all()
        self.data = [{'Address': item.__dict__['Address'],'PrivateKey': item.__dict__['PrivateKey']} for item in result]
                
        self.cols = 1
        self.rows = len(self.data)
        

    def display(self):
        self.clear_widgets()
        for item in self.data:
            row = self.create_detail(item)
            self.add_widget(row)
            

    def create_detail(self, item):
        btn = Button(text=item['Address'])
        btn.background_color = [0,0,0,0]
        btn.bind(on_press=lambda self: self.parent.switch_to_address(self.text))
        return btn

    def switch_to_address(self,address):
        app = App.get_running_app()
        app.root.ids.main_sm.ids.Main_Screen.ids.sm.current = 'QRAddressScreen'
        app.root.ids.main_sm.ids.Main_Screen.ids.sm.ids.QRAddress_Screen.ids.qr.data = address
        app.root.ids.main_sm.ids.Main_Screen.ids.sm.ids.QRAddress_Screen.ids.recieve_address.text = address

    def update_list(self):
        self.clear_widgets()
        self.bind(minimum_height=self.setter('height'))
        self.fetch_data_from_database()
        self.display()


class PayScreen(Screen):
    def pay_to_address(self):
        address = self.ids.pay_address.text
        amount = self.ids.amount.text
        result = session.query(UTXO).all()
        utxosets = [item.__dict__.copy() for item in result]
        print(utxosets)
        recieve_key = session.query(PrivateKeyList).filter_by(is_activated=True).one()
        output = create_transaction(utxosets,(address,int(amount)),recieve_key.Address)
        result = broadcast_tx(output['rawtx'])
        minerResponse = json.loads(result['data']['minerResponse']['payload'])
        if minerResponse['returnResult']=="success" or (result['data']['error']['message'] in ['257: txn-already-known','Transaction already in the mempool']):
            session.query(UTXO).delete()
            if output['utxoset']:
                output['utxoset']['PrivateKey'] = recieve_key.PrivateKey
                session.bulk_insert_mappings(UTXO,[output['utxoset']])
            output['is_recieved'] = False 
            query = session.query(TxHistory).filter_by(txid=output['txid']).all()
            if query:
                pass
            else:
                session.bulk_insert_mappings(TxHistory,[output])
            session.commit()
        print(output)
        print(result)

        #print(output['utxoset'])
        

    def pay_all_to_address(self):
        address = self.ids.pay_address.text
        result = session.query(UTXO).all()
        utxosets = [item.__dict__.copy() for item in result]
        output = sweep(utxosets,address)
        result = broadcast_tx(output['rawtx'])
        minerResponse = json.loads(result['data']['minerResponse']['payload'])
        if minerResponse['returnResult']=="success" or (result['data']['error']['message'] in ['257: txn-already-known','Transaction already in the mempool']):
            output['is_recieved'] = False
            session.query(UTXO).delete()
            query = session.query(TxHistory).filter_by(txid=output['txid']).all()
            if query:
                pass
            else:
                session.bulk_insert_mappings(TxHistory,[output])
            session.commit()
        print(output)
        print(result)
    
    def show_pay(self):
        pass

    def show_pay_all(self):
        pass


class RecieveScreen(Screen):
    pass

class ScanScreen(Screen):
    def scan_fun(self,text):
        app = App.get_running_app()
        if app.root.ids.main_sm.ids.Main_Screen.ids.sm.current == 'RecieveScreen':
            self.scantogetpaid(text)
        elif app.root.ids.main_sm.ids.Main_Screen.ids.sm.current == 'PayScreen':
            self.detect_address(text)

    def scantogetpaid(self,text):
        #print(self.ids.qrcontent.text)
        try:
            qrcontent = ast.literal_eval(text[2:-1])
            if all([(item in list(qrcontent.keys())) for item in ['version','input','output','lock_time']]):
                print(qrcontent)
                app = App.get_running_app()
                app.root.ids.main_sm.current = 'MainScreen'
                self.ids.zbarcam.stop()
                result = session.query(PrivateKeyList).filter_by(is_activated=True).one()
                prik = result.__dict__.copy()
                address = prik['Address']
                output = get_rawtx_to_pay(qrcontent,address)
                result = broadcast_tx(output['rawtx'])
                print(result)
                minerResponse = json.loads(result['data']['minerResponse']['payload'])
                if minerResponse['returnResult']=="success":
                    output['is_recieved'] = True
                    output['utxoset']['PrivateKey'] = prik['PrivateKey']
                    session.bulk_insert_mappings(UTXO,[output['utxoset']])
                    session.bulk_insert_mappings(TxHistory,[output])
                    session.commit()
                print(output)
                
                

                #do transfer
            else:
                print('wrong format!')
        except Exception as e:
            print(e)
            print('wrong QR code')

    def detect_address(self,text):
        try:
            #print(self.ids.qrcontent.text)
            address_group = re.search(r'\b[1][a-km-zA-HJ-NP-Z1-9]{25,34}\b',text)
            #print(address_group)
            address = address_group.group()
            #self.ids.pay_address.text = address
            if address!='':
                self.ids.zbarcam.stop()
                app = App.get_running_app()
                app.root.ids.main_sm.ids.Main_Screen.ids.sm.ids.Pay_Screen.ids.pay_address.text  = address
                app.root.ids.main_sm.current = 'MainScreen'
                
                #do transfer
            
        except Exception as e:
            print(e)
            print('wrong QR code')





class RV(ScrollView):
    def __init__(self, **kwargs):
        super(RV, self).__init__(**kwargs)
        
        


class HistoryView(GridLayout):
    
    def __init__(self, **kwargs):
        super(HistoryView, self).__init__(**kwargs)
        
        self.bind(minimum_height=self.setter('height'))
        self.fetch_data_from_database()
        self.display()
        
    def fetch_data_from_database(self):
        result = session.query(TxHistory).order_by(TxHistory.id.desc()).all()
        if len(result)==0:
            self.data = [
                {'is_recieved': 'None', 'txid': 'None', 'amount': 'None'}
            ]
        else:
            self.data = [{'is_recieved': item.__dict__['is_recieved'], 'txid': item.__dict__['txid'], 'amount': item.__dict__['amount']} for item in result]
                
        self.cols = 5
        self.rows = 2*len(self.data)
        

    def display(self):
        self.clear_widgets()
        for item in self.data:
            row = self.create_detail(item)
            for col in row:
                self.add_widget(col)
            

    def create_detail(self, item):
        col = []
        if item['is_recieved']==True:
            first_column = Label(text='Recieved')
        elif item['is_recieved']==False:
            first_column = Label(text='Paid')
        else:
            first_column = Label(text=item['is_recieved'])
        
        second_column = Label(text=str(item['amount']))
        
        third_column = Button(text=item['txid'])
        third_column.background_color = [0,0,0,0]
        
        third_column.fbind('on_press',lambda self: webbrowser.open('https://whatsonchain.com/tx/'+self.text))
        col.append(Label(text=''))
        col.append(first_column)
        for i in range(1):
            col.append(Label(text=''))
        col.append(second_column)
        col.append(Label(text=''))
        for i in range(2):
            col.append(Button(text='',background_color = [0,0,0,0],on_press=lambda self: webbrowser.open('https://whatsonchain.com/tx/'+item['txid'])))
        col.append(third_column)
        for i in range(2):
            col.append(Button(text='',background_color = [0,0,0,0],on_press=lambda self: webbrowser.open('https://whatsonchain.com/tx/'+item['txid'])))
        #print(len(col))
        return col
        #return [first_column, second_column, third_column,fourth_column]

    def update_list(self):
        self.clear_widgets()
        self.bind(minimum_height=self.setter('height'))
        self.fetch_data_from_database()
        self.display()





    


class app1(App):
    def build(self):
        pass
    

if __name__ == '__main__':
    app1().run()
    