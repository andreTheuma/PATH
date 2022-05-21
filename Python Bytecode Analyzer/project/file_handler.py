import os

class file_handler:
    
    def save_to_csv(self, relation, facts_type):
        """saves a relation of tuples into a facts file

        Args:
            relation (set(_,_)): Relations to save
            facts_type (String): Name of file
        """
        save_path = os.getcwd() + "/resources/" + facts_type + ".facts"

        f=open(save_path,'w')

        f.write('\n'.join('%s\t%s' % tuple for tuple in relation))
    
    def save_to_csv_three_tuple(self, relation, facts_type):
        """saves a relation of tuples into a facts file

        Args:
            relation (set(_,_)): Relations to save
            facts_type (String): Name of file
        """
        save_path = os.getcwd() + "/resources/" + facts_type + ".facts"

        f=open(save_path,'w')

        f.write('\n'.join(('%s\t%s\t%d' %tuple) for tuple in relation))
    
    def save_to_csv_three_tuple_string(self, relation, facts_type):
        """saves a relation of tuples into a facts file

        Args:
            relation (set(_,_)): Relations to save
            facts_type (String): Name of file
        """
        save_path = os.getcwd() + "/resources/" + facts_type + ".facts"

        f=open(save_path,'w')

        f.write('\n'.join(('%s\t%s\t%s' %tuple) for tuple in relation))
    
    def save_to_csv_five_tuple(self, relation, facts_type):
        """saves a relation of tuples into a facts file

        Args:
            relation (set(_,_)): Relations to save
            facts_type (String): Name of file
        """
        save_path = os.getcwd() + "/resources/" + facts_type + ".facts"

        f=open(save_path,'w')

        f.write('\n'.join(('%s\t%s\t%s\t\t%f\t\t%s' %tuple) for tuple in relation))
