

def normalize_list(_list):
	out_list = []
	_sum = sum(_list)

	for idx in xrange(len(_list)):
		if _list[idx] == 0:
			out_list.append(0)
		else:
			out_list.append( "%2.4f" % (float(idx)/_sum))
			#norm_list = ["%6.2f" % (float(i)/sum(two_gram_list)) for i in two_gram_list]

	return out_list

a = [1,2,3,4,5]
print normalize_list(a)