/**
 * The Accord Project, http://accordproject.org
 * Copyright (C) 2005-2013 Rafael Marins, http://rafaelmarins.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 *  $Id$
 */
package org.neociclo.odetteftp.oftplet;

import org.neociclo.odetteftp.protocol.AnswerReason;

import java.io.Serializable;

public interface EndFileResponse extends Serializable {

    /**
     * @return if this is a positive or negative end file esponse
     */
    boolean accepted();

    /**
     * @return reason for negative end file response
     */
    AnswerReason getReason();

    /**
     * @return description for negative end file response
     */
    String getReasonText();

    /**
     * @return if a change direction (CD) must be peformed
     */
    boolean changeDirection();

}
