import { Field, InputType } from '@nestjs/graphql';

import { ArticleUncheckedUpdateManyWithoutTagsInput } from '../article/article-unchecked-update-many-without-tags.input';

@InputType()
export class TagUncheckedUpdateInput {
    @Field(() => String, { nullable: true })
    tagId?: string;

    @Field(() => String, { nullable: true })
    name?: string;

    @Field(() => ArticleUncheckedUpdateManyWithoutTagsInput, { nullable: true })
    articles?: ArticleUncheckedUpdateManyWithoutTagsInput;
}
