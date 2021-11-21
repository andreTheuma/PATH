import os

class file_handler:
    
    def save_to_csv(self, relation, facts_type):
    
        save_path = os.getcwd() + "/Python Bytecode Analyzer/resources/" + facts_type + ".facts"

        f=open(save_path,'w')
        #writer = csv.writer(f)

        f.write('\n'.join('%s, %s' % tuple for tuple in relation))
