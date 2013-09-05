/*******************************************************************************************
 * Copyright (c) 2006-7 Laboratorio di Sistemi di Elaborazione e Bioingegneria Informatica *
 *                      Universita' Campus BioMedico - Italy                               *
 *                                                                                         *
 * This program is free software; you can redistribute it and/or modify it under the terms *
 * of the GNU General Public License as published by the Free Software Foundation; either  *
 * version 2 of the License, or (at your option) any later version.                        *
 *                                                                                         *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY         *
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A         *
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.                *
 *                                                                                         *
 * You should have received a copy of the GNU General Public License along with this       *
 * program; if not, write to the:                                                          *
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,                    *
 * MA  02111-1307, USA.                                                                    *
 *                                                                                         *
 * --------------------------------------------------------------------------------------- *
 * Project:  Capwap                                                                        *
 *                                                                                         *
 * Author :  Ludovico Rossi (ludo@bluepixysw.com)                                          *
 *           Del Moro Andrea (andrea_delmoro@libero.it)                                    *
 *           Giovannini Federica (giovannini.federica@gmail.com)                           *
 *           Massimo Vellucci (m.vellucci@unicampus.it)                                    *
 *           Mauro Bisson (mauro.bis@gmail.com)                                            *
 *******************************************************************************************/

#include "CWCommon.h"

// adds an element at the head of the list
// CW_TRUE if the operation is successful, CW_FALSE otherwise
CWBool CWAddElementToList(const void *ctx, CWList * list, void *element)
{
	CWListElement *newElem;

	if (element == NULL || list == NULL)
		return CW_FALSE;

	if ((*list) == NULL) {	// first element
		if (!((*list) = ralloc(ctx, CWListElement)))
			return CW_FALSE;

		(*list)->data = element;
		(*list)->next = NULL;
		return CW_TRUE;
	}

	if (!(newElem = ralloc(ctx, CWListElement)))
		return CW_FALSE;

	newElem->data = element;
	newElem->next = (*list);

	(*list) = newElem;

	return CW_TRUE;
}

// adds an element at the tail of the list
// CW_TRUE if the operation is successful, CW_FALSE otherwise
CWBool CWAddElementToListTail(const void *ctx, CWList * list, void *element)
{
	CWListElement *newElem;

	if (element == NULL || list == NULL)
		return CW_FALSE;

	if ((*list) == NULL) {	// first element
		if (!((*list) = ralloc(ctx, CWListElement)))
			return CW_FALSE;

		(*list)->data = element;
		(*list)->next = NULL;
		return CW_TRUE;
	}

	newElem = *list;
	while (newElem->next != NULL) {
		newElem = newElem->next;
	}

	if (!(newElem->next = ralloc(ctx, CWListElement)))
		return CW_FALSE;

	newElem->next->data = element;
	newElem->next->next = NULL;

	return CW_TRUE;
}

CWList CWListGetFirstElem(CWList * list)
{
	CWList auxList;

	if (list == NULL || *list == NULL)
		return NULL;

	auxList = *list;
	*list = (*list)->next;
	auxList->next = NULL;

	return auxList;
}

// not thread safe!
void *CWListGetNext(CWList list, CWListIterateMode mode)
{
	static CWList l = NULL;
	void *data;

	if (list == NULL)
		return NULL;

	if (mode == CW_LIST_ITERATE_RESET) {
		l = list;
	} else if (l == NULL)
		return NULL;

	data = l->data;
	l = l->next;

	return data;
}

// search baseElement in list using compareFunc
// NULL if there was an error, the element otherwise
void *CWSearchInList(CWList list, void *baseElement, CWBool(*compareFunc) (const void *, const void *))
{
	CWListElement *el = NULL;

	if (baseElement == NULL || compareFunc == NULL)
		return NULL;

	for (el = list; el != NULL; el = el->next) {
		if (compareFunc(baseElement, el->data)) {
			return el->data;
		}
	}

	return NULL;
}

// search baseElement in list using compareFunc, removes the element from the list and returns it
// NULL if there was an error, the element otherwise
void *CWDeleteInList(CWList * list, void *baseElement, CWBool(*compareFunc) (const void *, const void *))
{
	CWListElement *el = NULL, *oldEl = NULL;

	if (baseElement == NULL || compareFunc == NULL || list == NULL)
		return NULL;

	for (el = (*list); el != NULL; oldEl = el, el = el->next) {
		if (compareFunc(baseElement, el->data)) {
			void *data = el->data;
			if (oldEl != NULL) {
				oldEl->next = el->next;

				CW_FREE_OBJECT(el);
				return data;
			} else {	// first element
				(*list) = el->next;

				CW_FREE_OBJECT(el);
				return data;
			}

		}
	}

	return NULL;
}

// deletes a list, deleting each element with a call to the given deleteFunc
void CWDeleteList(CWList * list, void (*deleteFunc) (void *))
{
	CWListElement *el = NULL;

	if (list == NULL || (*list) == NULL || deleteFunc == NULL)
		return;

	do {
		el = (*list);
		(*list) = (*list)->next;
		deleteFunc(el->data);
		CW_FREE_OBJECT(el);
	} while ((*list) != NULL);
}

int CWCountElementInList(CWList list)
{
	CWListElement *current;
	int count = 0;

	current = list;
	while (current != NULL) {
		count++;
		current = current->next;
	}
	return count;
}

/*
CWList *FindLastElementInList (CWList list)
{
    CWListElement *current;

    current=list;
    while (current!= NULL) {current= current->next;}
    return &current;
}
*/
